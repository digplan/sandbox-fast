#ifndef SBX_H
#define SBX_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SBX_PAGE_SIZE       16384U
#define SBX_MAX_CONTAINERS  64
#define SBX_MAX_PATH        256
#define SBX_MAX_TOKEN       512
#define SBX_MAX_REQ         4096
#define SBX_MAX_RESP        8192
#define SBX_MAX_DFA         12288

#define SBX_RUNTIME_DIR     "/private/tmp/sbx-fast"
#define SBX_SHM_FILE        "/private/tmp/sbx-fast/shm.bin"
#define SBX_DFA_CACHE_FILE  "/private/tmp/sbx-fast/profile.dfa"

typedef enum {
    SBX_CREATE_HOT  = 0, /* Pre-cloned APFS CoW + pre-sandboxed worker checkout (~0.8 us) */
    SBX_CREATE_WARM = 1, /* On-demand APFS clonefileat + XNU token + pre-sandboxed worker (~75 us) */
    SBX_CREATE_COLD = 2  /* On-demand APFS clonefileat + fork + XNU DFA apply (~320 us) */
} sbx_create_mode_t;

typedef enum {
    SBX_EXEC_AUTO   = 0, /* Auto-dispatch: direct builtin if simple, else persistent /bin/sh */
    SBX_EXEC_DIRECT = 1, /* In-sandbox zero-fork builtin execution over SHM+ulock (~0.6 us) */
    SBX_EXEC_SHELL  = 2, /* Persistent in-sandbox /bin/sh coprocess execution (~15 us) */
    SBX_EXEC_SPAWN  = 3  /* Full external binary posix_spawn inside sandbox (~650 us) */
} sbx_exec_mode_t;

typedef enum {
    SBX_MOUNT_RW  = 0, /* Live read-write map via XNU read-write extension token + symlink */
    SBX_MOUNT_RO  = 1, /* Live read-only map via XNU read-only extension token + symlink */
    SBX_MOUNT_COW = 2  /* Isolated APFS Copy-on-Write clonefile snapshot into container */
} sbx_mount_mode_t;

typedef enum {
    SBX_SLOT_FREE         = 0,
    SBX_SLOT_WARM_WAITING = 1, /* Pre-sandboxed worker waiting for APFS rootfs + token */
    SBX_SLOT_BIND_REQ     = 2, /* Controller wrote token + cpath; worker should consume & chdir */
    SBX_SLOT_HOT_READY    = 3, /* Pre-staged worker already bound to CoW rootfs */
    SBX_SLOT_READY        = 4, /* Active container ready for commands */
    SBX_SLOT_EXEC_REQ     = 5, /* Client wrote command request */
    SBX_SLOT_EXEC_DONE    = 6, /* Worker completed command and wrote response */
    SBX_SLOT_VERIFY_REQ   = 7, /* Run in-sandbox security isolation self-test */
    SBX_SLOT_VERIFY_DONE  = 8, /* Security isolation self-test finished */
    SBX_SLOT_RESET_REQ    = 9, /* Revoke kernel capability token (sandbox_extension_release) & return to WARM */
    SBX_SLOT_EXIT         = 10,/* Terminate container worker */
    SBX_SLOT_MOUNT_REQ    = 11,/* Map/mount a local host directory into the container */
    SBX_SLOT_MOUNT_DONE   = 12 /* Local host directory mount completed */
} sbx_slot_state_t;

/*
 * Each container slot occupies exactly one 16 KB Apple Silicon hardware page.
 * Before calling sandbox_apply_bytecode(), each worker unmaps all other slots
 * and the control page so hardware MMU page tables isolate its IPC memory.
 */
typedef struct __attribute__((aligned(SBX_PAGE_SIZE))) sbx_slot {
    _Atomic uint32_t state;
    uint32_t         slot_id;
    pid_t            worker_pid;
    uint32_t         create_mode;
    uint32_t         exec_mode;
    int32_t          exit_code;
    uint32_t         req_len;
    uint32_t         resp_len;
    uint64_t         exec_count;
    uint64_t         last_create_ns;
    uint64_t         last_exec_ns;
    char             name[32];
    char             cpath[SBX_MAX_PATH];
    char             token[SBX_MAX_TOKEN];
    char             req[SBX_MAX_REQ];
    char             resp[SBX_MAX_RESP];
} sbx_slot_t;

_Static_assert(sizeof(sbx_slot_t) == SBX_PAGE_SIZE, "sbx_slot_t must be exactly one 16KB page");

/* Daemon IPC command codes on the control page */
#define SBX_DAEMON_IDLE        0U
#define SBX_DAEMON_REQ_CREATE  1U
#define SBX_DAEMON_REQ_DESTROY 2U
#define SBX_DAEMON_REQ_REPLEN  3U
#define SBX_DAEMON_REQ_STOP    4U
#define SBX_DAEMON_RESP_OK     5U
#define SBX_DAEMON_RESP_ERR    6U

typedef struct __attribute__((aligned(SBX_PAGE_SIZE))) sbx_control_page {
    uint32_t         magic;
    pid_t            daemon_pid;
    _Atomic uint32_t cmd_state;
    uint32_t         cmd_arg1;     /* create_mode or slot_id */
    int32_t          cmd_result;   /* allocated slot_id or error code */
    uint64_t         cmd_latency_ns;
    uint32_t         dfa_len;
    char             root_dir[SBX_MAX_PATH];
    char             base_dir[SBX_MAX_PATH];
    uint8_t          dfa_bytes[SBX_MAX_DFA];
} sbx_control_page_t;

_Static_assert(sizeof(sbx_control_page_t) == SBX_PAGE_SIZE, "sbx_control_page_t must be exactly one 16KB page");

typedef struct sbx_shm {
    sbx_control_page_t ctrl;
    sbx_slot_t         slots[SBX_MAX_CONTAINERS];
} sbx_shm_t;

typedef struct sbx_engine {
    int        shm_fd;
    int        root_dir_fd;
    int        is_owner;
    sbx_shm_t *shm;
} sbx_engine_t;

typedef struct sbx_isolation_report {
    int write_inside_ok;
    int write_outside_blocked;
    int read_users_blocked;
    int network_blocked;
    int spawn_inherit_ok;
    int cow_base_untouched;
} sbx_isolation_report_t;

/* High-resolution monotonic clock in nanoseconds / microseconds */
uint64_t sbx_now_ns(void);
double   sbx_now_us(void);

/* Engine lifecycle */
int  sbx_engine_init(sbx_engine_t *eng, int warm_pool_size, int hot_pool_size);
int  sbx_engine_attach(sbx_engine_t *eng);
void sbx_engine_close(sbx_engine_t *eng);
void sbx_engine_destroy_all(sbx_engine_t *eng);

/* Pool pre-warming */
int  sbx_pool_prepare_warm(sbx_engine_t *eng, int slot_id);
int  sbx_pool_prepare_hot(sbx_engine_t *eng, int slot_id);

/* Container lifecycle & execution (direct engine call) */
int  sbx_create(sbx_engine_t *eng, sbx_create_mode_t mode, uint64_t *latency_ns_out);
int  sbx_exec(sbx_engine_t *eng, int slot_id, sbx_exec_mode_t mode,
              const char *cmd, char *out_buf, size_t out_cap,
              int *exit_code_out, uint64_t *latency_ns_out);
int  sbx_mount(sbx_engine_t *eng, int slot_id, const char *host_path,
               const char *mount_name, sbx_mount_mode_t mode, uint64_t *latency_ns_out);
int  sbx_destroy(sbx_engine_t *eng, int slot_id);
int  sbx_recycle_warm(sbx_engine_t *eng, int slot_id);
int  sbx_recycle_hot(sbx_engine_t *eng, int slot_id);
int  sbx_verify_isolation(sbx_engine_t *eng, int slot_id, sbx_isolation_report_t *rep);

/* Daemon client operations (via control page ulock) */
int  sbx_daemon_start_background(int warm_count, int hot_count);
int  sbx_daemon_create(sbx_engine_t *eng, sbx_create_mode_t mode, uint64_t *latency_ns_out);
int  sbx_daemon_destroy(sbx_engine_t *eng, int slot_id);
int  sbx_daemon_stop(sbx_engine_t *eng);

#ifdef __cplusplus
}
#endif

#endif /* SBX_H */
