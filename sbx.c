#include "sbx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <spawn.h>
#include <fts.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/clonefile.h>
#include <mach/mach_time.h>
#include <mach-o/dyld.h>
#include <libgen.h>

extern char **environ;

/* Darwin kernel ulock (futex) in libsystem_kernel.dylib */
#define UL_COMPARE_AND_WAIT_SHARED 3
#define ULF_NO_ERRNO               0x01000000
extern int __ulock_wait(uint32_t operation, void *addr, uint64_t value, uint32_t timeout_us);
extern int __ulock_wake(uint32_t operation, void *addr, uint64_t wake_value);

/* XNU MAC policy syscall in libsystem_kernel.dylib */
extern int __mac_syscall(const char *policy, int call, void *arg);

/* Private libsandbox.1.dylib / libsystem_sandbox.dylib symbols */
typedef struct sandbox_profile_raw {
    char  *builtin_name;
    void  *bytecode;
    size_t bytecode_len;
} *sandbox_profile_t;

typedef struct sandbox_params *sandbox_params_t;
extern sandbox_params_t  sandbox_create_params(void);
extern void              sandbox_free_params(sandbox_params_t);
extern sandbox_profile_t sandbox_compile_string(const char *profile_str, sandbox_params_t params, char **error);
extern void              sandbox_free_profile(sandbox_profile_t profile);
extern int               sandbox_apply_bytecode(const void *bytecode, size_t bytecode_len, const char *name);
extern int64_t           sandbox_extension_consume(const char *token);
extern int               sandbox_extension_release(int64_t handle);

struct mac_ext_issue_args {
    const char *ext_class;
    uint64_t    ext_type;
    const char *data;
    uint64_t    flags;
    char       *out_token;
    int64_t     pid;
    uint64_t    pid_ver;
};

#define SBX_MAGIC       0x53425846U /* 'SBXF' */
#define SBX_DFA_MAGIC   0x53444642U /* 'SDFB' */

uint64_t sbx_now_ns(void) {
    static mach_timebase_info_data_t tb;
    if (__builtin_expect(tb.denom == 0, 0)) {
        mach_timebase_info(&tb);
    }
    return (mach_absolute_time() * tb.numer) / tb.denom;
}

double sbx_now_us(void) {
    return (double)sbx_now_ns() / 1000.0;
}

static inline void sbx_state_wait(_Atomic uint32_t *addr, uint32_t target) {
    for (int i = 0; i < 4000; i++) {
        if (atomic_load_explicit(addr, memory_order_acquire) == target) return;
        __builtin_arm_yield();
    }
    while (1) {
        uint32_t cur = atomic_load_explicit(addr, memory_order_acquire);
        if (cur == target) return;
        __ulock_wait(UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, (void *)addr, cur, 1000);
    }
}

static inline void sbx_state_set_wake(_Atomic uint32_t *addr, uint32_t val) {
    atomic_store_explicit(addr, val, memory_order_release);
    __ulock_wake(UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, (void *)addr, 0);
}

/*
 * Direct XNU __mac_syscall("Sandbox", 5) into caller-provided buffer.
 * Avoids libsystem_sandbox's 16 KB malloc() + free() on every container creation.
 */
static inline int sbx_issue_file_token_ext(const char *ext_class, const char *canonical_path, char *out_token_buf) {
    struct mac_ext_issue_args args = {
        .ext_class = ext_class,
        .ext_type  = 0,
        .data      = canonical_path,
        .flags     = 0,
        .out_token = out_token_buf,
        .pid       = 0,
        .pid_ver   = 0
    };
    return __mac_syscall("Sandbox", 5, &args);
}

static inline int sbx_issue_file_token_fast(const char *canonical_path, char *out_token_buf) {
    return sbx_issue_file_token_ext("com.apple.app-sandbox.read-write", canonical_path, out_token_buf);
}

static int rm_rf_dir(const char *path) {
    char *paths[] = { (char *)path, NULL };
    FTS *ftsp = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR | FTS_XDEV, NULL);
    if (!ftsp) return -1;
    FTSENT *curr;
    while ((curr = fts_read(ftsp)) != NULL) {
        switch (curr->fts_info) {
            case FTS_DP:
                rmdir(curr->fts_accpath);
                break;
            case FTS_F:
            case FTS_SL:
            case FTS_SLNONE:
            case FTS_DEFAULT:
                unlink(curr->fts_accpath);
                break;
            default:
                break;
        }
    }
    fts_close(ftsp);
    return 0;
}

static void fast_rm_rootfs(int root_dir_fd, const char *name, const char *cpath) {
    if (!cpath || cpath[0] == '\0') return;
    if (root_dir_fd >= 0 && name && name[0] != '\0') {
        char rel[64];
        snprintf(rel, sizeof(rel), "%s/etc/hostname", name); unlinkat(root_dir_fd, rel, 0);
        snprintf(rel, sizeof(rel), "%s/bin", name);          unlinkat(root_dir_fd, rel, AT_REMOVEDIR);
        snprintf(rel, sizeof(rel), "%s/etc", name);          unlinkat(root_dir_fd, rel, AT_REMOVEDIR);
        snprintf(rel, sizeof(rel), "%s/home", name);         unlinkat(root_dir_fd, rel, AT_REMOVEDIR);
        snprintf(rel, sizeof(rel), "%s/tmp", name);          unlinkat(root_dir_fd, rel, AT_REMOVEDIR);
        snprintf(rel, sizeof(rel), "%s/var", name);          unlinkat(root_dir_fd, rel, AT_REMOVEDIR);
        if (unlinkat(root_dir_fd, name, AT_REMOVEDIR) == 0 || errno == ENOENT) {
            return;
        }
    }
    rm_rf_dir(cpath);
}

/*
 * Load pre-compiled XNU Sandbox DFA bytecode from /private/tmp/sbx-fast/profile.dfa,
 * or compile once via libsandbox and cache to disk.
 */
static int load_or_compile_dfa(uint8_t *out_buf, uint32_t *out_len) {
    int fd = open(SBX_DFA_CACHE_FILE, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        uint32_t hdr[2];
        if (read(fd, hdr, sizeof(hdr)) == sizeof(hdr) &&
            hdr[0] == SBX_DFA_MAGIC && hdr[1] > 0 && hdr[1] <= SBX_MAX_DFA) {
            ssize_t n = read(fd, out_buf, hdr[1]);
            close(fd);
            if (n == (ssize_t)hdr[1]) {
                *out_len = hdr[1];
                return 0;
            }
        } else {
            close(fd);
        }
    }

    char exe_raw[1024];
    char exe_real[1024];
    uint32_t exe_sz = sizeof(exe_raw);
    const char *allow_dir = "/Users/chris/sandbox-fast";
    char allow_dir_buf[1024];
    if (_NSGetExecutablePath(exe_raw, &exe_sz) == 0 && realpath(exe_raw, exe_real) != NULL) {
        snprintf(allow_dir_buf, sizeof(allow_dir_buf), "%s", dirname(exe_real));
        allow_dir = allow_dir_buf;
    }

    char sbpl[2048];
    snprintf(sbpl, sizeof(sbpl),
        "(version 1)\n"
        "(allow default)\n"
        "(deny network*)\n"
        "(deny file-write*)\n"
        "(deny file-read* (subpath \"/Users\"))\n"
        "(allow file-read* (subpath \"%s\"))\n"
        "(allow file-write* (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/tty\"))\n"
        "(allow file-read* file-write* (extension \"com.apple.app-sandbox.read-write\"))\n"
        "(allow file-read* (extension \"com.apple.app-sandbox.read\"))\n",
        allow_dir);

    char *err = NULL;
    sandbox_params_t params = sandbox_create_params();
    sandbox_profile_t prof = sandbox_compile_string(sbpl, params, &err);
    sandbox_free_params(params);
    if (!prof || !prof->bytecode || prof->bytecode_len == 0 || prof->bytecode_len > SBX_MAX_DFA) {
        fprintf(stderr, "sbx: sandbox_compile_string failed: %s\n", err ? err : "unknown");
        return -1;
    }

    memcpy(out_buf, prof->bytecode, prof->bytecode_len);
    *out_len = (uint32_t)prof->bytecode_len;
    sandbox_free_profile(prof);

    int wfd = open(SBX_DFA_CACHE_FILE, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (wfd >= 0) {
        uint32_t hdr[2] = { SBX_DFA_MAGIC, *out_len };
        (void)write(wfd, hdr, sizeof(hdr));
        (void)write(wfd, out_buf, *out_len);
        close(wfd);
    }
    return 0;
}

static void prepare_template_rootfs(const char *base_dir) {
    mkdir(base_dir, 0755);
    char sub[SBX_MAX_PATH];
    snprintf(sub, sizeof(sub), "%s/bin", base_dir);  mkdir(sub, 0755);
    snprintf(sub, sizeof(sub), "%s/etc", base_dir);  mkdir(sub, 0755);
    snprintf(sub, sizeof(sub), "%s/home", base_dir); mkdir(sub, 0755);
    snprintf(sub, sizeof(sub), "%s/tmp", base_dir);  mkdir(sub, 0777);
    snprintf(sub, sizeof(sub), "%s/var", base_dir);  mkdir(sub, 0755);

    snprintf(sub, sizeof(sub), "%s/etc/hostname", base_dir);
    int fd = open(sub, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
    if (fd >= 0) {
        (void)write(fd, "sandbox-fast\n", 13);
        close(fd);
    }
}

/*
 * Check if a command string requires a full shell (pipes, redirects, subshells, quotes, etc.)
 */
static inline int cmd_needs_shell(const char *cmd) {
    for (const char *p = cmd; *p; p++) {
        char c = *p;
        if (c == '|' || c == '&' || c == ';' || c == '<' || c == '>' ||
            c == '$' || c == '`' || c == '(' || c == ')' || c == '\'' ||
            c == '"' || c == '*' || c == '?' || c == '\n' || c == '\\') {
            return 1;
        }
    }
    return 0;
}

/*
 * Fast-path in-sandbox native command execution.
 * Runs inside the already-sandboxed container worker process with zero fork overhead.
 * Returns 1 if handled directly, 0 if caller should fall back to persistent /bin/sh.
 */
static int worker_exec_direct(sbx_slot_t *slot, int allow_fallback) {
    const char *req = slot->req;
    while (*req == ' ' || *req == '\t') req++;

    if (*req == '\0' || strcmp(req, "true") == 0 || strcmp(req, ":") == 0) {
        slot->resp[0] = '\0';
        slot->resp_len = 0;
        slot->exit_code = 0;
        return 1;
    }
    if (strcmp(req, "false") == 0) {
        slot->resp[0] = '\0';
        slot->resp_len = 0;
        slot->exit_code = 1;
        return 1;
    }
    if (strcmp(req, "echo") == 0) {
        slot->resp[0] = '\n';
        slot->resp[1] = '\0';
        slot->resp_len = 1;
        slot->exit_code = 0;
        return 1;
    }
    if (strncmp(req, "echo ", 5) == 0) {
        const char *arg = req + 5;
        int no_nl = 0;
        if (strncmp(arg, "-n ", 3) == 0) {
            no_nl = 1;
            arg += 3;
        }
        size_t len = strlen(arg);
        if (len + 2 > SBX_MAX_RESP) len = SBX_MAX_RESP - 2;
        memcpy(slot->resp, arg, len);
        if (!no_nl) slot->resp[len++] = '\n';
        slot->resp[len] = '\0';
        slot->resp_len = (uint32_t)len;
        slot->exit_code = 0;
        return 1;
    }
    if (strcmp(req, "pwd") == 0) {
        if (getcwd(slot->resp, SBX_MAX_RESP - 2)) {
            size_t len = strlen(slot->resp);
            slot->resp[len++] = '\n';
            slot->resp[len] = '\0';
            slot->resp_len = (uint32_t)len;
            slot->exit_code = 0;
        } else {
            slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "pwd: %s\n", strerror(errno));
            slot->exit_code = 1;
        }
        return 1;
    }
    if (strncmp(req, "cd ", 3) == 0) {
        const char *target = req + 3;
        while (*target == ' ') target++;
        if (chdir(target) == 0) {
            char cwd[SBX_MAX_PATH];
            if (getcwd(cwd, sizeof(cwd))) setenv("PWD", cwd, 1);
            slot->resp[0] = '\0';
            slot->resp_len = 0;
            slot->exit_code = 0;
        } else {
            slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "cd: %s: %s\n", target, strerror(errno));
            slot->exit_code = 1;
        }
        return 1;
    }
    if (strcmp(req, "hostname") == 0) {
        slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "sbx-%02u\n", slot->slot_id);
        slot->exit_code = 0;
        return 1;
    }
    if (strcmp(req, "uname") == 0 || strcmp(req, "uname -s") == 0) {
        memcpy(slot->resp, "Darwin\n", 8);
        slot->resp_len = 7;
        slot->exit_code = 0;
        return 1;
    }
    if (strcmp(req, "id") == 0) {
        slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "uid=%u gid=%u\n", getuid(), getgid());
        slot->exit_code = 0;
        return 1;
    }
    if (strncmp(req, "mkdir ", 6) == 0) {
        const char *dir = req + 6;
        if (strncmp(dir, "-p ", 3) == 0) dir += 3;
        while (*dir == ' ') dir++;
        if (mkdir(dir, 0755) == 0 || errno == EEXIST) {
            slot->resp[0] = '\0';
            slot->resp_len = 0;
            slot->exit_code = 0;
        } else {
            slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "mkdir: %s: %s\n", dir, strerror(errno));
            slot->exit_code = 1;
        }
        return 1;
    }
    if (strncmp(req, "touch ", 6) == 0) {
        const char *path = req + 6;
        while (*path == ' ') path++;
        int fd = open(path, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) {
            close(fd);
            slot->resp[0] = '\0';
            slot->resp_len = 0;
            slot->exit_code = 0;
        } else {
            slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "touch: %s: %s\n", path, strerror(errno));
            slot->exit_code = 1;
        }
        return 1;
    }
    if (strncmp(req, "write ", 6) == 0) {
        const char *p = req + 6;
        while (*p == ' ') p++;
        const char *sp = strchr(p, ' ');
        if (sp) {
            char fname[SBX_MAX_PATH];
            size_t flen = (size_t)(sp - p);
            if (flen >= sizeof(fname)) flen = sizeof(fname) - 1;
            memcpy(fname, p, flen);
            fname[flen] = '\0';
            const char *content = sp + 1;
            int fd = open(fname, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd >= 0) {
                size_t clen = strlen(content);
                (void)write(fd, content, clen);
                (void)write(fd, "\n", 1);
                close(fd);
                slot->resp[0] = '\0';
                slot->resp_len = 0;
                slot->exit_code = 0;
            } else {
                slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "write: %s: %s\n", fname, strerror(errno));
                slot->exit_code = 1;
            }
            return 1;
        }
    }
    if (strncmp(req, "cat ", 4) == 0) {
        const char *path = req + 4;
        while (*path == ' ') path++;
        if (!strchr(path, ' ')) {
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                ssize_t n = read(fd, slot->resp, SBX_MAX_RESP - 1);
                close(fd);
                if (n < 0) n = 0;
                slot->resp[n] = '\0';
                slot->resp_len = (uint32_t)n;
                slot->exit_code = 0;
            } else {
                slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "cat: %s: %s\n", path, strerror(errno));
                slot->exit_code = 1;
            }
            return 1;
        }
    }
    if (strncmp(req, "rm ", 3) == 0) {
        const char *path = req + 3;
        if (strncmp(path, "-f ", 3) == 0) path += 3;
        while (*path == ' ') path++;
        if (!strchr(path, ' ')) {
            if (unlink(path) == 0 || rmdir(path) == 0) {
                slot->resp[0] = '\0';
                slot->resp_len = 0;
                slot->exit_code = 0;
            } else {
                slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "rm: %s: %s\n", path, strerror(errno));
                slot->exit_code = 1;
            }
            return 1;
        }
    }
    if (strcmp(req, "ls") == 0 || strncmp(req, "ls ", 3) == 0) {
        const char *path = (strcmp(req, "ls") == 0) ? "." : (req + 3);
        while (*path == ' ') path++;
        if (*path != '-') {
            DIR *d = opendir(*path ? path : ".");
            if (d) {
                size_t off = 0;
                struct dirent *de;
                while ((de = readdir(d)) != NULL) {
                    if (de->d_name[0] == '.' &&
                        (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
                        continue;
                    }
                    int w = snprintf(slot->resp + off, SBX_MAX_RESP - off, "%s\n", de->d_name);
                    if (w <= 0 || off + (size_t)w >= SBX_MAX_RESP) break;
                    off += (size_t)w;
                }
                closedir(d);
                slot->resp[off] = '\0';
                slot->resp_len = (uint32_t)off;
                slot->exit_code = 0;
                return 1;
            } else {
                slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "ls: %s: %s\n", path, strerror(errno));
                slot->exit_code = 1;
                return 1;
            }
        }
    }
    if (strcmp(req, "env") == 0) {
        size_t off = 0;
        for (char **e = environ; e && *e; e++) {
            int w = snprintf(slot->resp + off, SBX_MAX_RESP - off, "%s\n", *e);
            if (w <= 0 || off + (size_t)w >= SBX_MAX_RESP) break;
            off += (size_t)w;
        }
        slot->resp[off] = '\0';
        slot->resp_len = (uint32_t)off;
        slot->exit_code = 0;
        return 1;
    }
    if (strncmp(req, "export ", 7) == 0) {
        char kv[256];
        snprintf(kv, sizeof(kv), "%s", req + 7);
        char *eq = strchr(kv, '=');
        if (eq) {
            *eq = '\0';
            setenv(kv, eq + 1, 1);
            slot->resp[0] = '\0';
            slot->resp_len = 0;
            slot->exit_code = 0;
            return 1;
        }
    }

    if (allow_fallback) return 0;

    slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "direct: unsupported builtin: %s\n", req);
    slot->exit_code = 127;
    return 1;
}

/*
 * Persistent in-sandbox /bin/sh coprocess execution (~15 us per shell command).
 * Spawns /bin/sh once inside the sandboxed container and reuses stdin/stdout pipes.
 */
static void worker_exec_shell(sbx_slot_t *slot, pid_t *sh_pid, int *sh_in_fd, int *sh_out_fd) {
    if (*sh_pid <= 0) {
        int in_p[2], out_p[2];
        if (pipe(in_p) != 0 || pipe(out_p) != 0) {
            slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "pipe failed\n");
            slot->exit_code = 1;
            return;
        }
        pid_t pid = fork();
        if (pid == 0) {
            dup2(in_p[0], STDIN_FILENO);
            dup2(out_p[1], STDOUT_FILENO);
            dup2(out_p[1], STDERR_FILENO);
            close(in_p[0]); close(in_p[1]);
            close(out_p[0]); close(out_p[1]);
            execl("/bin/sh", "sh", NULL);
            _exit(127);
        }
        close(in_p[0]);
        close(out_p[1]);
        fcntl(in_p[1], F_SETFD, FD_CLOEXEC);
        fcntl(out_p[0], F_SETFD, FD_CLOEXEC);
        *sh_pid = pid;
        *sh_in_fd = in_p[1];
        *sh_out_fd = out_p[0];
    }

    char wrapped[SBX_MAX_REQ + 64];
    int wlen = snprintf(wrapped, sizeof(wrapped), "%s\nprintf '\\036%%d\\037' $?\n", slot->req);
    if (write(*sh_in_fd, wrapped, (size_t)wlen) != wlen) {
        slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "shell write error\n");
        slot->exit_code = 1;
        return;
    }

    size_t total = 0;
    slot->exit_code = 0;
    while (total < SBX_MAX_RESP - 1) {
        ssize_t n = read(*sh_out_fd, slot->resp + total, SBX_MAX_RESP - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
        slot->resp[total] = '\0';
        char *mark = memchr(slot->resp, '\036', total);
        if (mark) {
            char *end = memchr(mark + 1, '\037', total - (size_t)(mark - slot->resp) - 1);
            if (end) {
                *end = '\0';
                slot->exit_code = atoi(mark + 1);
                *mark = '\0';
                total = (size_t)(mark - slot->resp);
                break;
            }
        }
    }
    slot->resp_len = (uint32_t)total;
}

/*
 * Full external Mach-O binary spawn inside the sandbox via posix_spawn.
 * Directly spawns the binary if no shell metacharacters are present, else uses /bin/sh -c.
 */
static void worker_exec_spawn(sbx_slot_t *slot) {
    int pfd[2];
    if (pipe(pfd) != 0) {
        slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "pipe error\n");
        slot->exit_code = 1;
        return;
    }

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&fa, pfd[0]);
    posix_spawn_file_actions_addclose(&fa, pfd[1]);

    pid_t cpid = -1;
    int rc = -1;

    if (!cmd_needs_shell(slot->req)) {
        char cmd_copy[SBX_MAX_REQ];
        snprintf(cmd_copy, sizeof(cmd_copy), "%s", slot->req);
        char *argv[64];
        int argc = 0;
        char *saveptr = NULL;
        char *tok = strtok_r(cmd_copy, " \t", &saveptr);
        while (tok && argc < 63) {
            argv[argc++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr);
        }
        argv[argc] = NULL;
        if (argc > 0) {
            char bin_path[SBX_MAX_PATH];
            if (argv[0][0] == '/') {
                snprintf(bin_path, sizeof(bin_path), "%s", argv[0]);
            } else {
                snprintf(bin_path, sizeof(bin_path), "/bin/%s", argv[0]);
                if (access(bin_path, X_OK) != 0) {
                    snprintf(bin_path, sizeof(bin_path), "/usr/bin/%s", argv[0]);
                }
            }
            rc = posix_spawn(&cpid, bin_path, &fa, NULL, argv, environ);
        }
    }

    if (rc != 0) {
        char *sh_argv[] = { "/bin/sh", "-c", slot->req, NULL };
        rc = posix_spawn(&cpid, "/bin/sh", &fa, NULL, sh_argv, environ);
    }

    posix_spawn_file_actions_destroy(&fa);
    close(pfd[1]);

    if (rc != 0) {
        close(pfd[0]);
        slot->resp_len = (uint32_t)snprintf(slot->resp, SBX_MAX_RESP, "posix_spawn failed: %s\n", strerror(rc));
        slot->exit_code = 127;
        return;
    }

    size_t total = 0;
    while (total < SBX_MAX_RESP - 1) {
        ssize_t n = read(pfd[0], slot->resp + total, SBX_MAX_RESP - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    slot->resp[total] = '\0';
    slot->resp_len = (uint32_t)total;
    close(pfd[0]);

    int status = 0;
    waitpid(cpid, &status, 0);
    slot->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/*
 * Run in-sandbox kernel security & isolation checks from inside the container worker.
 */
static void worker_run_verify(sbx_slot_t *slot) {
    sbx_isolation_report_t rep;
    memset(&rep, 0, sizeof(rep));

    /* 1. Write inside container CoW rootfs -> MUST SUCCEED */
    int fd_in = open("sbx_verify_probe.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_in >= 0) {
        (void)write(fd_in, "isolated\n", 9);
        close(fd_in);
        rep.write_inside_ok = 1;
    }

    /* 2. Write outside container (/private/tmp) -> MUST BE BLOCKED BY XNU MAC (EPERM) */
    int fd_out = open("/private/tmp/sbx_escape_attempt.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_out < 0 && errno == EPERM) {
        rep.write_outside_blocked = 1;
    } else if (fd_out >= 0) {
        close(fd_out);
        unlink("/private/tmp/sbx_escape_attempt.txt");
    }

    /* 3. Read host /Users directory -> MUST BE BLOCKED BY XNU MAC (EPERM) */
    int fd_usr = open("/Users/chris/AGENTS.md", O_RDONLY);
    if (fd_usr < 0 && errno == EPERM) {
        rep.read_users_blocked = 1;
    } else if (fd_usr >= 0) {
        close(fd_usr);
    }

    /* 4. Outbound network socket -> MUST BE BLOCKED BY XNU MAC (EPERM) */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 && errno == EPERM) {
        rep.network_blocked = 1;
    } else if (sock >= 0) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(80);
        sin.sin_addr.s_addr = inet_addr("1.1.1.1");
        int crc = connect(sock, (struct sockaddr *)&sin, sizeof(sin));
        if (crc < 0 && errno == EPERM) {
            rep.network_blocked = 1;
        }
        close(sock);
    }

    /* 5. Verify posix_spawn child inherits both container write extension AND outside write ban */
    char *argv_ok[] = { "/bin/sh", "-c", "echo child_ok > sbx_child_verify.txt", NULL };
    pid_t cpid1 = -1;
    if (posix_spawn(&cpid1, "/bin/sh", NULL, NULL, argv_ok, environ) == 0) {
        int st1 = 0;
        waitpid(cpid1, &st1, 0);
        char *argv_bad[] = { "/bin/sh", "-c", "touch /private/tmp/sbx_child_escape.txt 2>/dev/null", NULL };
        pid_t cpid2 = -1;
        if (posix_spawn(&cpid2, "/bin/sh", NULL, NULL, argv_bad, environ) == 0) {
            int st2 = 0;
            waitpid(cpid2, &st2, 0);
            if (WIFEXITED(st1) && WEXITSTATUS(st1) == 0 &&
                WIFEXITED(st2) && WEXITSTATUS(st2) != 0) {
                rep.spawn_inherit_ok = 1;
            }
        }
    }

    memcpy(slot->resp, &rep, sizeof(rep));
    slot->resp_len = sizeof(rep);
    slot->exit_code = 0;
}

/*
 * Container worker main loop.
 * worker_kind:
 *   0 = WARM pool worker (enters XNU DFA sandbox immediately, waits for token+cpath)
 *   1 = HOT pool worker  (enters XNU DFA sandbox + consumes token + chdir, waits for checkout)
 *   2 = COLD worker      (cpath+token already in slot; enters sandbox + consumes + chdir -> READY)
 */
__attribute__((noreturn))
static void worker_main(sbx_shm_t *shm, int slot_id, int worker_kind) {
    setpgid(0, 0);

    /* Copy DFA bytecode onto stack before unmapping the control page */
    uint32_t dfa_len = shm->ctrl.dfa_len;
    uint8_t dfa_local[SBX_MAX_DFA];
    memcpy(dfa_local, shm->ctrl.dfa_bytes, dfa_len);

    sbx_slot_t *slot = &shm->slots[slot_id];

    /* Hardware MMU page isolation: unmap control page and all other container slots */
    munmap(&shm->ctrl, SBX_PAGE_SIZE);
    if (slot_id > 0) {
        munmap(&shm->slots[0], (size_t)slot_id * SBX_PAGE_SIZE);
    }
    if (slot_id + 1 < SBX_MAX_CONTAINERS) {
        munmap(&shm->slots[slot_id + 1], (size_t)(SBX_MAX_CONTAINERS - 1 - slot_id) * SBX_PAGE_SIZE);
    }

    /* Apply resource limits */
    struct rlimit rl_core = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl_core);

    /* Pre-populate container environment before entering wait loop */
    char tmp_env[SBX_MAX_PATH + 16];
    snprintf(tmp_env, sizeof(tmp_env), "%s/tmp", slot->cpath);
    setenv("HOME", slot->cpath, 1);
    setenv("PWD", slot->cpath, 1);
    setenv("TMPDIR", tmp_env, 1);
    setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1);

    /* Lock process into XNU kernel MAC sandbox via pre-compiled DFA bytecode */
    if (sandbox_apply_bytecode(dfa_local, dfa_len, NULL) != 0) {
        _exit(101);
    }

    pid_t sh_pid = -1;
    int sh_in_fd = -1;
    int sh_out_fd = -1;
    int64_t ext_handle = -1;
    int64_t mount_handles[8];
    int mount_count = 0;

warm_loop:
    if (worker_kind == 0) {
        /* Signal that this worker is pre-sandboxed and waiting for APFS rootfs + token */
        sbx_state_set_wake(&slot->state, SBX_SLOT_WARM_WAITING);

        /* Spin-then-ulock wait for controller to bind us (SBX_SLOT_BIND_REQ) or exit */
        for (int i = 0; i < 4000; i++) {
            uint32_t st = atomic_load_explicit(&slot->state, memory_order_acquire);
            if (st == SBX_SLOT_BIND_REQ || st == SBX_SLOT_EXIT) goto bind_now;
            __builtin_arm_yield();
        }
        while (1) {
            uint32_t st = atomic_load_explicit(&slot->state, memory_order_acquire);
            if (st == SBX_SLOT_BIND_REQ || st == SBX_SLOT_EXIT) break;
            __ulock_wait(UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, (void *)&slot->state, st, 5000);
        }
    bind_now:
        if (atomic_load_explicit(&slot->state, memory_order_relaxed) == SBX_SLOT_EXIT) {
            _exit(0);
        }
    }

    /* Consume kernel-signed file capability token & enter container rootfs */
    ext_handle = sandbox_extension_consume(slot->token);
    if (ext_handle < 0) {
        _exit(102);
    }
    if (chdir(slot->cpath) != 0) {
        _exit(103);
    }

    if (worker_kind == 1) {
        sbx_state_set_wake(&slot->state, SBX_SLOT_HOT_READY);
    } else {
        sbx_state_set_wake(&slot->state, SBX_SLOT_READY);
    }

    /* Main command loop */
    while (1) {
        uint32_t st = 0;
        for (int i = 0; i < 4000; i++) {
            st = atomic_load_explicit(&slot->state, memory_order_acquire);
            if (st == SBX_SLOT_EXEC_REQ || st == SBX_SLOT_VERIFY_REQ ||
                st == SBX_SLOT_MOUNT_REQ || st == SBX_SLOT_RESET_REQ || st == SBX_SLOT_EXIT) {
                goto dispatch;
            }
            __builtin_arm_yield();
        }
        while (1) {
            st = atomic_load_explicit(&slot->state, memory_order_acquire);
            if (st == SBX_SLOT_EXEC_REQ || st == SBX_SLOT_VERIFY_REQ ||
                st == SBX_SLOT_MOUNT_REQ || st == SBX_SLOT_RESET_REQ || st == SBX_SLOT_EXIT) {
                goto dispatch;
            }
            __ulock_wait(UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, (void *)&slot->state, st, 2000);
        }

    dispatch:
        if (st == SBX_SLOT_EXIT) break;

        if (st == SBX_SLOT_RESET_REQ) {
            if (sh_pid > 0) {
                close(sh_in_fd);
                close(sh_out_fd);
                kill(sh_pid, SIGKILL);
                waitpid(sh_pid, NULL, 0);
                sh_pid = -1;
            }
            (void)chdir("/");
            for (int m = 0; m < mount_count; m++) {
                sandbox_extension_release(mount_handles[m]);
            }
            mount_count = 0;
            if (ext_handle >= 0) {
                sandbox_extension_release(ext_handle);
                ext_handle = -1;
            }
            worker_kind = 0;
            goto warm_loop;
        }

        if (st == SBX_SLOT_MOUNT_REQ) {
            int64_t mh = sandbox_extension_consume(slot->token);
            if (mh >= 0 && mount_count < 8) {
                mount_handles[mount_count++] = mh;
            }
            unlink(slot->resp);
            int s_rc = symlink(slot->req, slot->resp);
            slot->exit_code = (mh >= 0 && s_rc == 0) ? 0 : -1;
            sbx_state_set_wake(&slot->state, SBX_SLOT_MOUNT_DONE);
            continue;
        }

        if (st == SBX_SLOT_VERIFY_REQ) {
            worker_run_verify(slot);
            sbx_state_set_wake(&slot->state, SBX_SLOT_VERIFY_DONE);
            continue;
        }

        uint32_t emode = slot->exec_mode;
        if (emode == SBX_EXEC_DIRECT) {
            worker_exec_direct(slot, 0);
        } else if (emode == SBX_EXEC_AUTO) {
            if (cmd_needs_shell(slot->req) || !worker_exec_direct(slot, 1)) {
                worker_exec_shell(slot, &sh_pid, &sh_in_fd, &sh_out_fd);
            }
        } else if (emode == SBX_EXEC_SHELL) {
            worker_exec_shell(slot, &sh_pid, &sh_in_fd, &sh_out_fd);
        } else {
            worker_exec_spawn(slot);
        }

        slot->exec_count++;
        sbx_state_set_wake(&slot->state, SBX_SLOT_EXEC_DONE);
    }

    if (sh_pid > 0) {
        close(sh_in_fd);
        close(sh_out_fd);
        kill(sh_pid, SIGKILL);
        waitpid(sh_pid, NULL, 0);
    }
    _exit(0);
}

int sbx_pool_prepare_warm(sbx_engine_t *eng, int slot_id) {
    if (slot_id < 0 || slot_id >= SBX_MAX_CONTAINERS) return -1;
    sbx_slot_t *slot = &eng->shm->slots[slot_id];
    memset(slot, 0, sizeof(*slot));
    slot->slot_id = (uint32_t)slot_id;
    snprintf(slot->name, sizeof(slot->name), "sbx-%02d", slot_id);
    snprintf(slot->cpath, sizeof(slot->cpath), "%s/%s", eng->shm->ctrl.root_dir, slot->name);

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        close(eng->shm_fd);
        close(eng->root_dir_fd);
        worker_main(eng->shm, slot_id, 0);
    }
    slot->worker_pid = pid;
    sbx_state_wait(&slot->state, SBX_SLOT_WARM_WAITING);
    return 0;
}

int sbx_pool_prepare_hot(sbx_engine_t *eng, int slot_id) {
    if (slot_id < 0 || slot_id >= SBX_MAX_CONTAINERS) return -1;
    sbx_slot_t *slot = &eng->shm->slots[slot_id];
    memset(slot, 0, sizeof(*slot));
    slot->slot_id = (uint32_t)slot_id;
    snprintf(slot->name, sizeof(slot->name), "sbx-%02d", slot_id);
    snprintf(slot->cpath, sizeof(slot->cpath), "%s/%s", eng->shm->ctrl.root_dir, slot->name);

    if (unlinkat(eng->root_dir_fd, slot->name, AT_REMOVEDIR) != 0 && errno != ENOENT) {
        rm_rf_dir(slot->cpath);
    }
    if (clonefileat(eng->root_dir_fd, "base_rootfs", eng->root_dir_fd, slot->name, 0) != 0) {
        return -1;
    }
    if (sbx_issue_file_token_fast(slot->cpath, slot->token) != 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        close(eng->shm_fd);
        close(eng->root_dir_fd);
        worker_main(eng->shm, slot_id, 1);
    }
    slot->worker_pid = pid;
    sbx_state_wait(&slot->state, SBX_SLOT_HOT_READY);
    return 0;
}

int sbx_engine_init(sbx_engine_t *eng, int warm_pool_size, int hot_pool_size) {
    memset(eng, 0, sizeof(*eng));
    mkdir(SBX_RUNTIME_DIR, 0755);

    char canonical_root[SBX_MAX_PATH];
    if (!realpath(SBX_RUNTIME_DIR, canonical_root)) {
        return -1;
    }

    char base_dir[SBX_MAX_PATH];
    snprintf(base_dir, sizeof(base_dir), "%s/base_rootfs", canonical_root);
    prepare_template_rootfs(base_dir);

    int rfd = open(canonical_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rfd < 0) return -1;

    int sfd = open(SBX_SHM_FILE, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    if (sfd < 0) {
        close(rfd);
        return -1;
    }
    if (ftruncate(sfd, sizeof(sbx_shm_t)) != 0) {
        close(sfd);
        close(rfd);
        return -1;
    }

    sbx_shm_t *shm = mmap(NULL, sizeof(sbx_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0);
    if (shm == MAP_FAILED) {
        close(sfd);
        close(rfd);
        return -1;
    }

    memset(shm, 0, sizeof(*shm));
    shm->ctrl.magic = SBX_MAGIC;
    shm->ctrl.daemon_pid = getpid();
    snprintf(shm->ctrl.root_dir, sizeof(shm->ctrl.root_dir), "%s", canonical_root);
    snprintf(shm->ctrl.base_dir, sizeof(shm->ctrl.base_dir), "%s", base_dir);

    if (load_or_compile_dfa(shm->ctrl.dfa_bytes, &shm->ctrl.dfa_len) != 0) {
        munmap(shm, sizeof(sbx_shm_t));
        close(sfd);
        close(rfd);
        return -1;
    }

    eng->shm_fd = sfd;
    eng->root_dir_fd = rfd;
    eng->is_owner = 1;
    eng->shm = shm;

    int idx = 0;
    for (int i = 0; i < hot_pool_size && idx < SBX_MAX_CONTAINERS; i++, idx++) {
        sbx_pool_prepare_hot(eng, idx);
    }
    for (int i = 0; i < warm_pool_size && idx < SBX_MAX_CONTAINERS; i++, idx++) {
        sbx_pool_prepare_warm(eng, idx);
    }
    return 0;
}

int sbx_engine_attach(sbx_engine_t *eng) {
    memset(eng, 0, sizeof(*eng));
    int sfd = open(SBX_SHM_FILE, O_RDWR | O_CLOEXEC);
    if (sfd < 0) return -1;

    sbx_shm_t *shm = mmap(NULL, sizeof(sbx_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0);
    if (shm == MAP_FAILED) {
        close(sfd);
        return -1;
    }
    if (shm->ctrl.magic != SBX_MAGIC) {
        munmap(shm, sizeof(sbx_shm_t));
        close(sfd);
        return -1;
    }

    int rfd = open(shm->ctrl.root_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    eng->shm_fd = sfd;
    eng->root_dir_fd = rfd;
    eng->is_owner = 0;
    eng->shm = shm;
    return 0;
}

void sbx_engine_destroy_all(sbx_engine_t *eng) {
    if (!eng || !eng->shm) return;
    for (int i = 0; i < SBX_MAX_CONTAINERS; i++) {
        uint32_t st = atomic_load_explicit(&eng->shm->slots[i].state, memory_order_acquire);
        if (st != SBX_SLOT_FREE) {
            sbx_destroy(eng, i);
        }
    }
}

void sbx_engine_close(sbx_engine_t *eng) {
    if (!eng || !eng->shm) return;
    int owner = eng->is_owner;
    if (owner) {
        sbx_engine_destroy_all(eng);
        eng->shm->ctrl.magic = 0;
        eng->shm->ctrl.daemon_pid = 0;
    }
    munmap(eng->shm, sizeof(sbx_shm_t));
    if (eng->shm_fd >= 0) close(eng->shm_fd);
    if (eng->root_dir_fd >= 0) close(eng->root_dir_fd);
    if (owner) {
        unlink(SBX_SHM_FILE);
    }
    memset(eng, 0, sizeof(*eng));
}

int sbx_create(sbx_engine_t *eng, sbx_create_mode_t mode, uint64_t *latency_ns_out) {
    uint64_t t0 = sbx_now_ns();

    if (mode == SBX_CREATE_HOT) {
        for (int i = 0; i < SBX_MAX_CONTAINERS; i++) {
            sbx_slot_t *slot = &eng->shm->slots[i];
            uint32_t expected = SBX_SLOT_HOT_READY;
            if (atomic_compare_exchange_strong_explicit(
                    &slot->state, &expected, SBX_SLOT_READY,
                    memory_order_acq_rel, memory_order_relaxed)) {
                uint64_t dt = sbx_now_ns() - t0;
                slot->create_mode = SBX_CREATE_HOT;
                slot->last_create_ns = dt;
                if (latency_ns_out) *latency_ns_out = dt;
                return i;
            }
        }
        /* Fall through to WARM if no HOT slot is pre-staged */
    }

    if (mode == SBX_CREATE_WARM || mode == SBX_CREATE_HOT) {
        for (int i = 0; i < SBX_MAX_CONTAINERS; i++) {
            sbx_slot_t *slot = &eng->shm->slots[i];
            uint32_t st = atomic_load_explicit(&slot->state, memory_order_acquire);
            if (st == SBX_SLOT_WARM_WAITING) {
                snprintf(slot->cpath, sizeof(slot->cpath), "%s/%s", eng->shm->ctrl.root_dir, slot->name);
                if (clonefileat(eng->root_dir_fd, "base_rootfs", eng->root_dir_fd, slot->name, 0) != 0) {
                    rm_rf_dir(slot->cpath);
                    if (clonefileat(eng->root_dir_fd, "base_rootfs", eng->root_dir_fd, slot->name, 0) != 0) {
                        return -1;
                    }
                }
                if (sbx_issue_file_token_fast(slot->cpath, slot->token) != 0) {
                    return -1;
                }
                sbx_state_set_wake(&slot->state, SBX_SLOT_BIND_REQ);
                sbx_state_wait(&slot->state, SBX_SLOT_READY);
                uint64_t dt = sbx_now_ns() - t0;
                slot->create_mode = SBX_CREATE_WARM;
                slot->last_create_ns = dt;
                if (latency_ns_out) *latency_ns_out = dt;
                return i;
            }
        }
    }

    /* SBX_CREATE_COLD (or fallback when pools are empty): full clonefileat + fork + DFA apply */
    for (int i = 0; i < SBX_MAX_CONTAINERS; i++) {
        sbx_slot_t *slot = &eng->shm->slots[i];
        uint32_t st = atomic_load_explicit(&slot->state, memory_order_acquire);
        if (st == SBX_SLOT_FREE) {
            memset(slot, 0, sizeof(*slot));
            slot->slot_id = (uint32_t)i;
            snprintf(slot->name, sizeof(slot->name), "sbx-%02d", i);
            snprintf(slot->cpath, sizeof(slot->cpath), "%s/%s", eng->shm->ctrl.root_dir, slot->name);

            if (clonefileat(eng->root_dir_fd, "base_rootfs", eng->root_dir_fd, slot->name, 0) != 0) {
                rm_rf_dir(slot->cpath);
                if (clonefileat(eng->root_dir_fd, "base_rootfs", eng->root_dir_fd, slot->name, 0) != 0) {
                    return -1;
                }
            }
            if (sbx_issue_file_token_fast(slot->cpath, slot->token) != 0) {
                return -1;
            }

            atomic_store_explicit(&slot->state, SBX_SLOT_BIND_REQ, memory_order_release);
            pid_t pid = fork();
            if (pid < 0) {
                atomic_store_explicit(&slot->state, SBX_SLOT_FREE, memory_order_release);
                return -1;
            }
            if (pid == 0) {
                close(eng->shm_fd);
                close(eng->root_dir_fd);
                worker_main(eng->shm, i, 2);
            }
            slot->worker_pid = pid;
            sbx_state_wait(&slot->state, SBX_SLOT_READY);

            uint64_t dt = sbx_now_ns() - t0;
            slot->create_mode = SBX_CREATE_COLD;
            slot->last_create_ns = dt;
            if (latency_ns_out) *latency_ns_out = dt;
            return i;
        }
    }
    return -1;
}

int sbx_exec(sbx_engine_t *eng, int slot_id, sbx_exec_mode_t mode,
             const char *cmd, char *out_buf, size_t out_cap,
             int *exit_code_out, uint64_t *latency_ns_out) {
    if (slot_id < 0 || slot_id >= SBX_MAX_CONTAINERS || !cmd) return -1;
    sbx_slot_t *slot = &eng->shm->slots[slot_id];
    uint32_t st = atomic_load_explicit(&slot->state, memory_order_acquire);
    if (st != SBX_SLOT_READY && st != SBX_SLOT_EXEC_DONE &&
        st != SBX_SLOT_VERIFY_DONE && st != SBX_SLOT_MOUNT_DONE) {
        return -1;
    }

    uint64_t t0 = sbx_now_ns();
    size_t clen = strlen(cmd);
    if (clen >= SBX_MAX_REQ) clen = SBX_MAX_REQ - 1;
    memcpy(slot->req, cmd, clen);
    slot->req[clen] = '\0';
    slot->req_len = (uint32_t)clen;
    slot->exec_mode = (uint32_t)mode;

    sbx_state_set_wake(&slot->state, SBX_SLOT_EXEC_REQ);
    sbx_state_wait(&slot->state, SBX_SLOT_EXEC_DONE);
    uint64_t dt = sbx_now_ns() - t0;

    slot->last_exec_ns = dt;
    if (out_buf && out_cap > 0) {
        size_t copy_len = slot->resp_len;
        if (copy_len >= out_cap) copy_len = out_cap - 1;
        memcpy(out_buf, slot->resp, copy_len);
        out_buf[copy_len] = '\0';
    }
    if (exit_code_out) *exit_code_out = slot->exit_code;
    if (latency_ns_out) *latency_ns_out = dt;
    return 0;
}

int sbx_mount(sbx_engine_t *eng, int slot_id, const char *host_path,
              const char *mount_name, sbx_mount_mode_t mode, uint64_t *latency_ns_out) {
    if (slot_id < 0 || slot_id >= SBX_MAX_CONTAINERS || !host_path || !mount_name) return -1;
    sbx_slot_t *slot = &eng->shm->slots[slot_id];
    uint32_t st = atomic_load_explicit(&slot->state, memory_order_acquire);
    if (st != SBX_SLOT_READY && st != SBX_SLOT_EXEC_DONE &&
        st != SBX_SLOT_VERIFY_DONE && st != SBX_SLOT_MOUNT_DONE) {
        return -1;
    }

    char canonical_host[SBX_MAX_PATH];
    if (!realpath(host_path, canonical_host)) {
        return -1;
    }

    uint64_t t0 = sbx_now_ns();

    if (mode == SBX_MOUNT_COW) {
        char target_path[SBX_MAX_PATH * 2];
        snprintf(target_path, sizeof(target_path), "%s/%s", slot->cpath, mount_name);
        rm_rf_dir(target_path);
        if (clonefile(canonical_host, target_path, 0) != 0) {
            return -1;
        }
        uint64_t dt = sbx_now_ns() - t0;
        if (latency_ns_out) *latency_ns_out = dt;
        return 0;
    }

    const char *ext_cls = (mode == SBX_MOUNT_RO)
        ? "com.apple.app-sandbox.read"
        : "com.apple.app-sandbox.read-write";

    if (sbx_issue_file_token_ext(ext_cls, canonical_host, slot->token) != 0) {
        return -1;
    }

    snprintf(slot->req, sizeof(slot->req), "%s", canonical_host);
    snprintf(slot->resp, sizeof(slot->resp), "%s", mount_name);

    sbx_state_set_wake(&slot->state, SBX_SLOT_MOUNT_REQ);
    sbx_state_wait(&slot->state, SBX_SLOT_MOUNT_DONE);
    uint64_t dt = sbx_now_ns() - t0;

    if (latency_ns_out) *latency_ns_out = dt;
    return slot->exit_code;
}

int sbx_verify_isolation(sbx_engine_t *eng, int slot_id, sbx_isolation_report_t *rep) {
    if (slot_id < 0 || slot_id >= SBX_MAX_CONTAINERS || !rep) return -1;
    sbx_slot_t *slot = &eng->shm->slots[slot_id];

    sbx_state_set_wake(&slot->state, SBX_SLOT_VERIFY_REQ);
    sbx_state_wait(&slot->state, SBX_SLOT_VERIFY_DONE);

    if (slot->resp_len != sizeof(sbx_isolation_report_t)) return -1;
    memcpy(rep, slot->resp, sizeof(*rep));

    /* Verify on host that APFS CoW base_rootfs was untouched by container writes */
    char base_probe[SBX_MAX_PATH + 64];
    snprintf(base_probe, sizeof(base_probe), "%s/sbx_verify_probe.txt", eng->shm->ctrl.base_dir);
    struct stat st;
    rep->cow_base_untouched = (stat(base_probe, &st) != 0 && errno == ENOENT) ? 1 : 0;
    return 0;
}

int sbx_destroy(sbx_engine_t *eng, int slot_id) {
    if (slot_id < 0 || slot_id >= SBX_MAX_CONTAINERS) return -1;
    sbx_slot_t *slot = &eng->shm->slots[slot_id];
    uint32_t st = atomic_load_explicit(&slot->state, memory_order_acquire);
    if (st == SBX_SLOT_FREE) return 0;

    pid_t pid = slot->worker_pid;
    sbx_state_set_wake(&slot->state, SBX_SLOT_EXIT);
    if (pid > 0) {
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
        }
    }

    if (slot->cpath[0] != '\0') {
        fast_rm_rootfs(eng->root_dir_fd, slot->name, slot->cpath);
    }
    memset(slot, 0, sizeof(*slot));
    atomic_store_explicit(&slot->state, SBX_SLOT_FREE, memory_order_release);
    return 0;
}

int sbx_recycle_warm(sbx_engine_t *eng, int slot_id) {
    if (slot_id < 0 || slot_id >= SBX_MAX_CONTAINERS) return -1;
    sbx_slot_t *slot = &eng->shm->slots[slot_id];
    sbx_state_set_wake(&slot->state, SBX_SLOT_RESET_REQ);
    sbx_state_wait(&slot->state, SBX_SLOT_WARM_WAITING);
    if (slot->cpath[0] != '\0') {
        fast_rm_rootfs(eng->root_dir_fd, slot->name, slot->cpath);
    }
    slot->exec_count = 0;
    return 0;
}

int sbx_recycle_hot(sbx_engine_t *eng, int slot_id) {
    if (slot_id < 0 || slot_id >= SBX_MAX_CONTAINERS) return -1;
    sbx_slot_t *slot = &eng->shm->slots[slot_id];
    slot->exec_count = 0;
    atomic_store_explicit(&slot->state, SBX_SLOT_HOT_READY, memory_order_release);
    return 0;
}

/*
 * Background daemon loop: services create/destroy requests from external CLI clients
 * over the shared-memory control page and automatically replenishes warm/hot slots.
 */
int sbx_daemon_start_background(int warm_count, int hot_count) {
    sbx_engine_t probe;
    if (sbx_engine_attach(&probe) == 0) {
        pid_t dpid = probe.shm->ctrl.daemon_pid;
        sbx_engine_close(&probe);
        if (dpid > 0 && kill(dpid, 0) == 0) {
            return 0; /* Already running */
        }
    }

    int ready_pipe[2];
    if (pipe(ready_pipe) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        return -1;
    }
    if (pid > 0) {
        close(ready_pipe[1]);
        char ch = 0;
        ssize_t n = read(ready_pipe[0], &ch, 1);
        close(ready_pipe[0]);
        return (n == 1 && ch == 'R') ? 0 : -1;
    }

    close(ready_pipe[0]);
    setsid();

    sbx_engine_t eng;
    if (sbx_engine_init(&eng, warm_count, hot_count) != 0) {
        (void)write(ready_pipe[1], "E", 1);
        close(ready_pipe[1]);
        _exit(1);
    }

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2) close(devnull);
    }
    (void)write(ready_pipe[1], "R", 1);
    close(ready_pipe[1]);

    sbx_control_page_t *ctrl = &eng.shm->ctrl;
    while (1) {
        uint32_t cs = atomic_load_explicit(&ctrl->cmd_state, memory_order_acquire);
        if (cs == SBX_DAEMON_IDLE || cs == SBX_DAEMON_RESP_OK || cs == SBX_DAEMON_RESP_ERR) {
            __ulock_wait(UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, (void *)&ctrl->cmd_state, cs, 10000);
            continue;
        }
        if (cs == SBX_DAEMON_REQ_STOP) {
            sbx_state_set_wake(&ctrl->cmd_state, SBX_DAEMON_RESP_OK);
            break;
        }
        if (cs == SBX_DAEMON_REQ_CREATE) {
            uint64_t lat = 0;
            sbx_create_mode_t mode = (sbx_create_mode_t)ctrl->cmd_arg1;
            int id = sbx_create(&eng, mode, &lat);
            ctrl->cmd_result = id;
            ctrl->cmd_latency_ns = lat;
            sbx_state_set_wake(&ctrl->cmd_state, id >= 0 ? SBX_DAEMON_RESP_OK : SBX_DAEMON_RESP_ERR);

            /* Replenish a warm worker in a free slot after replying to client */
            for (int i = 0; i < SBX_MAX_CONTAINERS; i++) {
                if (atomic_load_explicit(&eng.shm->slots[i].state, memory_order_acquire) == SBX_SLOT_FREE) {
                    if (mode == SBX_CREATE_HOT) {
                        sbx_pool_prepare_hot(&eng, i);
                    } else {
                        sbx_pool_prepare_warm(&eng, i);
                    }
                    break;
                }
            }
        } else if (cs == SBX_DAEMON_REQ_DESTROY) {
            int slot_id = (int)ctrl->cmd_arg1;
            int rc = sbx_destroy(&eng, slot_id);
            ctrl->cmd_result = rc;
            sbx_state_set_wake(&ctrl->cmd_state, rc == 0 ? SBX_DAEMON_RESP_OK : SBX_DAEMON_RESP_ERR);
            sbx_pool_prepare_warm(&eng, slot_id);
        }
    }

    sbx_engine_close(&eng);
    unlink(SBX_SHM_FILE);
    _exit(0);
}

int sbx_daemon_create(sbx_engine_t *eng, sbx_create_mode_t mode, uint64_t *latency_ns_out) {
    sbx_control_page_t *ctrl = &eng->shm->ctrl;
    ctrl->cmd_arg1 = (uint32_t)mode;
    uint64_t t0 = sbx_now_ns();
    sbx_state_set_wake(&ctrl->cmd_state, SBX_DAEMON_REQ_CREATE);
    while (1) {
        uint32_t st = atomic_load_explicit(&ctrl->cmd_state, memory_order_acquire);
        if (st == SBX_DAEMON_RESP_OK || st == SBX_DAEMON_RESP_ERR) break;
        __builtin_arm_yield();
    }
    uint64_t dt = sbx_now_ns() - t0;
    int res = ctrl->cmd_result;
    atomic_store_explicit(&ctrl->cmd_state, SBX_DAEMON_IDLE, memory_order_release);
    if (latency_ns_out) *latency_ns_out = dt;
    return res;
}

int sbx_daemon_destroy(sbx_engine_t *eng, int slot_id) {
    sbx_control_page_t *ctrl = &eng->shm->ctrl;
    ctrl->cmd_arg1 = (uint32_t)slot_id;
    sbx_state_set_wake(&ctrl->cmd_state, SBX_DAEMON_REQ_DESTROY);
    while (1) {
        uint32_t st = atomic_load_explicit(&ctrl->cmd_state, memory_order_acquire);
        if (st == SBX_DAEMON_RESP_OK || st == SBX_DAEMON_RESP_ERR) break;
        __builtin_arm_yield();
    }
    int res = ctrl->cmd_result;
    atomic_store_explicit(&ctrl->cmd_state, SBX_DAEMON_IDLE, memory_order_release);
    return res;
}

int sbx_daemon_stop(sbx_engine_t *eng) {
    sbx_control_page_t *ctrl = &eng->shm->ctrl;
    sbx_state_set_wake(&ctrl->cmd_state, SBX_DAEMON_REQ_STOP);
    sbx_state_wait(&ctrl->cmd_state, SBX_DAEMON_RESP_OK);
    return 0;
}
