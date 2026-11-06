#include "sbx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

extern int sbx_run_benchmarks(void);

static void usage(const char *prog) {
    printf("Usage: %s <command> [args...]\n\n", prog);
    printf("Commands:\n");
    printf("  bench                              Run full creation, command & security benchmark suite\n");
    printf("  verify                             Run 6-point kernel & APFS CoW isolation self-test\n");
    printf("  create [hot|warm|cold]             Create a new sandbox container (auto-starts daemon)\n");
    printf("  mount [--rw|--ro|--cow] <id> <host_dir> [mount_name]\n");
    printf("                                     Map a local host directory into container <id>\n");
    printf("  exec [--direct|--shell|--spawn] <id> <cmd...>\n");
    printf("                                     Execute command in container <id> over SHM+ulock\n");
    printf("  run <cmd...>                       One-shot create + exec + destroy with latency report\n");
    printf("  ls                                 List active and pre-warmed sandbox containers\n");
    printf("  rm <id>                            Destroy sandbox container <id>\n");
    printf("  daemon <start|stop|status>         Manage background Zygote pool daemon\n");
}

static int ensure_daemon_attached(sbx_engine_t *eng) {
    if (sbx_engine_attach(eng) == 0) {
        pid_t dpid = eng->shm->ctrl.daemon_pid;
        if (dpid > 0 && kill(dpid, 0) == 0) {
            return 0;
        }
        sbx_engine_close(eng);
    }
    if (sbx_daemon_start_background(8, 4) != 0) {
        fprintf(stderr, "sbx: failed to start background daemon\n");
        return -1;
    }
    return sbx_engine_attach(eng);
}

static const char *slot_state_name(uint32_t st) {
    switch (st) {
        case SBX_SLOT_FREE:         return "FREE";
        case SBX_SLOT_WARM_WAITING: return "POOL_WARM";
        case SBX_SLOT_HOT_READY:    return "POOL_HOT";
        case SBX_SLOT_READY:
        case SBX_SLOT_EXEC_DONE:
        case SBX_SLOT_VERIFY_DONE:
        case SBX_SLOT_MOUNT_DONE:   return "RUNNING";
        default:                    return "BUSY";
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *sub = argv[1];

    if (strcmp(sub, "bench") == 0) {
        return sbx_run_benchmarks();
    }

    if (strcmp(sub, "verify") == 0) {
        sbx_engine_t eng;
        if (sbx_engine_init(&eng, 1, 0) != 0) {
            fprintf(stderr, "Failed to init engine\n");
            return 1;
        }
        uint64_t c_ns = 0;
        int id = sbx_create(&eng, SBX_CREATE_WARM, &c_ns);
        sbx_isolation_report_t rep;
        int rc = sbx_verify_isolation(&eng, id, &rep);
        sbx_destroy(&eng, id);
        sbx_engine_close(&eng);

        if (rc != 0) {
            fprintf(stderr, "Isolation verification failed\n");
            return 1;
        }
        printf("Container created in %.2f us (%.4f ms)\n", (double)c_ns / 1000.0, (double)c_ns / 1e6);
        printf("  [1] Write inside APFS CoW rootfs       : %s\n", rep.write_inside_ok ? "PASS" : "FAIL");
        printf("  [2] Write outside (/private/tmp) block : %s\n", rep.write_outside_blocked ? "PASS (EPERM)" : "FAIL");
        printf("  [3] Read host (/Users) block           : %s\n", rep.read_users_blocked ? "PASS (EPERM)" : "FAIL");
        printf("  [4] Outbound network block             : %s\n", rep.network_blocked ? "PASS (EPERM)" : "FAIL");
        printf("  [5] Child posix_spawn rule inheritance : %s\n", rep.spawn_inherit_ok ? "PASS" : "FAIL");
        printf("  [6] Base template rootfs untouched     : %s\n", rep.cow_base_untouched ? "PASS" : "FAIL");
        return (rep.write_inside_ok && rep.write_outside_blocked && rep.read_users_blocked &&
                rep.network_blocked && rep.spawn_inherit_ok && rep.cow_base_untouched) ? 0 : 1;
    }

    if (strcmp(sub, "daemon") == 0) {
        const char *act = (argc >= 3) ? argv[2] : "status";
        if (strcmp(act, "start") == 0) {
            if (sbx_daemon_start_background(8, 4) != 0) {
                fprintf(stderr, "Failed to start daemon\n");
                return 1;
            }
            sbx_engine_t eng;
            if (sbx_engine_attach(&eng) == 0) {
                printf("sbx daemon running (pid=%d, shm=%s)\n", eng.shm->ctrl.daemon_pid, SBX_SHM_FILE);
                sbx_engine_close(&eng);
            }
            return 0;
        } else if (strcmp(act, "stop") == 0) {
            sbx_engine_t eng;
            if (sbx_engine_attach(&eng) == 0 && eng.shm->ctrl.daemon_pid > 0 &&
                kill(eng.shm->ctrl.daemon_pid, 0) == 0) {
                sbx_daemon_stop(&eng);
                sbx_engine_close(&eng);
                printf("sbx daemon stopped\n");
            } else {
                unlink(SBX_SHM_FILE);
                printf("sbx daemon is not running\n");
            }
            return 0;
        } else {
            sbx_engine_t eng;
            if (sbx_engine_attach(&eng) == 0 && eng.shm->ctrl.daemon_pid > 0 &&
                kill(eng.shm->ctrl.daemon_pid, 0) == 0) {
                printf("sbx daemon is RUNNING (pid=%d, root=%s)\n",
                       eng.shm->ctrl.daemon_pid, eng.shm->ctrl.root_dir);
                sbx_engine_close(&eng);
                return 0;
            }
            printf("sbx daemon is STOPPED\n");
            return 0;
        }
    }

    if (strcmp(sub, "create") == 0) {
        sbx_create_mode_t mode = SBX_CREATE_HOT;
        if (argc >= 3) {
            if (strcmp(argv[2], "warm") == 0) mode = SBX_CREATE_WARM;
            else if (strcmp(argv[2], "cold") == 0) mode = SBX_CREATE_COLD;
        }
        sbx_engine_t eng;
        if (ensure_daemon_attached(&eng) != 0) return 1;
        uint64_t lat_ns = 0;
        int id = sbx_daemon_create(&eng, mode, &lat_ns);
        if (id < 0) {
            fprintf(stderr, "Failed to create container\n");
            sbx_engine_close(&eng);
            return 1;
        }
        printf("id=%d name=%s pid=%d rootfs=%s engine_create=%.3f_us total_ipc=%.2f_us (%.4f_ms)\n",
               id,
               eng.shm->slots[id].name,
               eng.shm->slots[id].worker_pid,
               eng.shm->slots[id].cpath,
               (double)eng.shm->slots[id].last_create_ns / 1000.0,
               (double)lat_ns / 1000.0,
               (double)lat_ns / 1e6);
        sbx_engine_close(&eng);
        return 0;
    }

    if (strcmp(sub, "mount") == 0) {
        int argi = 2;
        sbx_mount_mode_t mode = SBX_MOUNT_RW;
        if (argi < argc && strncmp(argv[argi], "--", 2) == 0) {
            if (strcmp(argv[argi], "--rw") == 0) mode = SBX_MOUNT_RW;
            else if (strcmp(argv[argi], "--ro") == 0) mode = SBX_MOUNT_RO;
            else if (strcmp(argv[argi], "--cow") == 0) mode = SBX_MOUNT_COW;
            argi++;
        }
        if (argc - argi < 2) {
            usage(argv[0]);
            return 1;
        }
        int slot_id = atoi(argv[argi++]);
        const char *host_dir = argv[argi++];
        const char *mount_name = (argi < argc) ? argv[argi] : "workspace";

        sbx_engine_t eng;
        if (sbx_engine_attach(&eng) != 0) {
            fprintf(stderr, "No running sbx daemon; run '%s create' first\n", argv[0]);
            return 1;
        }
        uint64_t lat_ns = 0;
        if (sbx_mount(&eng, slot_id, host_dir, mount_name, mode, &lat_ns) != 0) {
            fprintf(stderr, "Failed to mount '%s' into container %d\n", host_dir, slot_id);
            sbx_engine_close(&eng);
            return 1;
        }
        const char *mname = (mode == SBX_MOUNT_RO) ? "RO (XNU read token)" :
                            (mode == SBX_MOUNT_COW) ? "CoW (APFS clonefile)" :
                                                      "RW (XNU read-write token)";
        printf("Mounted '%s' -> container %d:/%s [%s] in %.2f us (%.4f ms)\n",
               host_dir, slot_id, mount_name, mname, (double)lat_ns / 1000.0, (double)lat_ns / 1e6);
        sbx_engine_close(&eng);
        return 0;
    }

    if (strcmp(sub, "exec") == 0) {
        int argi = 2;
        sbx_exec_mode_t mode = SBX_EXEC_AUTO;
        if (argi < argc && strncmp(argv[argi], "--", 2) == 0) {
            if (strcmp(argv[argi], "--direct") == 0) mode = SBX_EXEC_DIRECT;
            else if (strcmp(argv[argi], "--shell") == 0) mode = SBX_EXEC_SHELL;
            else if (strcmp(argv[argi], "--spawn") == 0) mode = SBX_EXEC_SPAWN;
            argi++;
        }
        if (argc - argi < 2) {
            usage(argv[0]);
            return 1;
        }
        int slot_id = atoi(argv[argi++]);
        char cmd[SBX_MAX_REQ] = {0};
        size_t off = 0;
        for (int i = argi; i < argc; i++) {
            int w = snprintf(cmd + off, sizeof(cmd) - off, "%s%s", (i > argi) ? " " : "", argv[i]);
            if (w > 0) off += (size_t)w;
        }

        sbx_engine_t eng;
        if (sbx_engine_attach(&eng) != 0) {
            fprintf(stderr, "No running sbx daemon; run '%s create' first\n", argv[0]);
            return 1;
        }

        char out[SBX_MAX_RESP];
        int exit_code = 0;
        uint64_t lat_ns = 0;
        if (sbx_exec(&eng, slot_id, mode, cmd, out, sizeof(out), &exit_code, &lat_ns) != 0) {
            fprintf(stderr, "Failed to exec on container %d (not in RUNNING state)\n", slot_id);
            sbx_engine_close(&eng);
            return 1;
        }
        if (out[0] != '\0') {
            fputs(out, stdout);
        }
        fprintf(stderr, "[sbx exec slot=%d exit=%d time=%.2f us (%.5f ms)]\n",
                slot_id, exit_code, (double)lat_ns / 1000.0, (double)lat_ns / 1e6);
        sbx_engine_close(&eng);
        return exit_code;
    }

    if (strcmp(sub, "run") == 0) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        char cmd[SBX_MAX_REQ] = {0};
        size_t off = 0;
        for (int i = 2; i < argc; i++) {
            int w = snprintf(cmd + off, sizeof(cmd) - off, "%s%s", (i > 2) ? " " : "", argv[i]);
            if (w > 0) off += (size_t)w;
        }

        sbx_engine_t eng;
        if (ensure_daemon_attached(&eng) != 0) return 1;

        uint64_t create_ns = 0, exec_ns = 0;
        int id = sbx_daemon_create(&eng, SBX_CREATE_HOT, &create_ns);
        if (id < 0) {
            sbx_engine_close(&eng);
            return 1;
        }
        uint64_t engine_create_ns = eng.shm->slots[id].last_create_ns;
        char out[SBX_MAX_RESP];
        int exit_code = 0;
        sbx_exec(&eng, id, SBX_EXEC_AUTO, cmd, out, sizeof(out), &exit_code, &exec_ns);
        if (out[0] != '\0') fputs(out, stdout);
        sbx_daemon_destroy(&eng, id);
        sbx_engine_close(&eng);

        fprintf(stderr, "[sbx run create=%.2f us (%.4f ms) | exec=%.2f us (%.5f ms) | exit=%d]\n",
                (double)engine_create_ns / 1000.0, (double)engine_create_ns / 1e6,
                (double)exec_ns / 1000.0, (double)exec_ns / 1e6, exit_code);
        return exit_code;
    }

    if (strcmp(sub, "ls") == 0) {
        sbx_engine_t eng;
        if (sbx_engine_attach(&eng) != 0) {
            printf("No active sbx daemon.\n");
            return 0;
        }
        printf("%-4s | %-8s | %-7s | %-10s | %-8s | %s\n",
               "ID", "NAME", "PID", "STATE", "EXECS", "ROOTFS");
        printf("-----+----------+---------+------------+----------+----------------------------------\n");
        for (int i = 0; i < SBX_MAX_CONTAINERS; i++) {
            sbx_slot_t *s = &eng.shm->slots[i];
            uint32_t st = atomic_load_explicit(&s->state, memory_order_acquire);
            if (st != SBX_SLOT_FREE) {
                printf("%-4d | %-8s | %-7d | %-10s | %-8llu | %s\n",
                       i, s->name, s->worker_pid, slot_state_name(st),
                       (unsigned long long)s->exec_count,
                       s->cpath[0] ? s->cpath : "(awaiting CoW bind)");
            }
        }
        sbx_engine_close(&eng);
        return 0;
    }

    if (strcmp(sub, "rm") == 0) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        int slot_id = atoi(argv[2]);
        sbx_engine_t eng;
        if (sbx_engine_attach(&eng) != 0) return 1;
        sbx_daemon_destroy(&eng, slot_id);
        sbx_engine_close(&eng);
        printf("Removed container %d\n", slot_id);
        return 0;
    }

    usage(argv[0]);
    return 1;
}
