#include "sbx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

typedef struct bench_stats {
    double min_us;
    double p50_us;
    double p95_us;
    double p99_us;
    double max_us;
    double mean_us;
} bench_stats_t;

static bench_stats_t compute_stats(uint64_t *samples_ns, int n) {
    qsort(samples_ns, (size_t)n, sizeof(uint64_t), cmp_u64);
    uint64_t sum = 0;
    for (int i = 0; i < n; i++) sum += samples_ns[i];

    bench_stats_t st;
    st.min_us  = (double)samples_ns[0] / 1000.0;
    st.p50_us  = (double)samples_ns[n / 2] / 1000.0;
    st.p95_us  = (double)samples_ns[(n * 95) / 100] / 1000.0;
    st.p99_us  = (double)samples_ns[(n * 99) / 100] / 1000.0;
    st.max_us  = (double)samples_ns[n - 1] / 1000.0;
    st.mean_us = ((double)sum / (double)n) / 1000.0;
    return st;
}

/*
 * Measure standard Apple /usr/bin/sandbox-exec baseline on this machine.
 */
static bench_stats_t bench_apple_sandbox_exec(int runs) {
    uint64_t *samples = calloc((size_t)runs, sizeof(uint64_t));
    for (int i = 0; i < runs; i++) {
        uint64_t t0 = sbx_now_ns();
        int pfd[2];
        pipe(pfd);
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_adddup2(&fa, pfd[1], STDOUT_FILENO);
        posix_spawn_file_actions_addclose(&fa, pfd[0]);
        posix_spawn_file_actions_addclose(&fa, pfd[1]);
        char *argv[] = {
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1)(allow default)(deny network*)(deny file-write*)",
            "/bin/echo",
            "baseline",
            NULL
        };
        pid_t pid = -1;
        posix_spawn(&pid, "/usr/bin/sandbox-exec", &fa, NULL, argv, environ);
        posix_spawn_file_actions_destroy(&fa);
        close(pfd[1]);
        char buf[64];
        while (read(pfd[0], buf, sizeof(buf)) > 0) {}
        close(pfd[0]);
        waitpid(pid, NULL, 0);
        samples[i] = sbx_now_ns() - t0;
    }
    bench_stats_t st = compute_stats(samples, runs);
    free(samples);
    return st;
}

int sbx_run_benchmarks(void) {
    printf("========================================================================================\n");
    printf("  sandbox-fast: Ultra-Low-Latency Darwin Kernel MAC + APFS CoW Container Benchmark\n");
    printf("========================================================================================\n\n");

    sbx_engine_t eng;
    if (sbx_engine_init(&eng, 0, 0) != 0) {
        fprintf(stderr, "Failed to initialize sandbox-fast engine\n");
        return 1;
    }

    /* 1. Security & Isolation Verification */
    uint64_t v_lat = 0;
    int vid = sbx_create(&eng, SBX_CREATE_COLD, &v_lat);
    sbx_isolation_report_t rep;
    if (vid < 0 || sbx_verify_isolation(&eng, vid, &rep) != 0) {
        fprintf(stderr, "Isolation verification failed to run\n");
        sbx_engine_close(&eng);
        return 1;
    }
    sbx_destroy(&eng, vid);

    printf("[1/4] Kernel & Filesystem Isolation Self-Test\n");
    printf("  - APFS CoW Rootfs Write Allowed Inside Container : %s\n", rep.write_inside_ok ? "PASS" : "FAIL");
    printf("  - Host Filesystem (/private/tmp) Write Blocked   : %s (EPERM)\n", rep.write_outside_blocked ? "PASS" : "FAIL");
    printf("  - Host Home Dir (/Users) Read Blocked            : %s (EPERM)\n", rep.read_users_blocked ? "PASS" : "FAIL");
    printf("  - Outbound Network Socket Blocked                : %s (EPERM)\n", rep.network_blocked ? "PASS" : "FAIL");
    printf("  - Child posix_spawn Inherits Sandbox & Extension : %s\n", rep.spawn_inherit_ok ? "PASS" : "FAIL");
    printf("  - APFS Base Template Rootfs Untouched (CoW)      : %s\n\n", rep.cow_base_untouched ? "PASS" : "FAIL");

    if (!rep.write_inside_ok || !rep.write_outside_blocked || !rep.read_users_blocked ||
        !rep.network_blocked || !rep.spawn_inherit_ok || !rep.cow_base_untouched) {
        fprintf(stderr, "ERROR: Security isolation invariant failed!\n");
        sbx_engine_close(&eng);
        return 1;
    }

    /* 2. Measure Apple /usr/bin/sandbox-exec baseline */
    const int N_BASELINE = 25;
    bench_stats_t st_apple = bench_apple_sandbox_exec(N_BASELINE);

    /* 3. Measure Container Creation across all 3 tiers */
    const int N_CREATE = 50;
    uint64_t *samples_cold = calloc((size_t)N_CREATE, sizeof(uint64_t));
    uint64_t *samples_warm = calloc((size_t)N_CREATE, sizeof(uint64_t));
    uint64_t *samples_hot  = calloc((size_t)N_CREATE, sizeof(uint64_t));

    /* 3a. Cold Create (live APFS clonefileat + fork + XNU DFA apply + token consume) */
    for (int i = 0; i < N_CREATE; i++) {
        int id = sbx_create(&eng, SBX_CREATE_COLD, &samples_cold[i]);
        sbx_destroy(&eng, id);
    }
    bench_stats_t st_create_cold = compute_stats(samples_cold, N_CREATE);

    /* 3b. Warm Zygote Create (pre-sandboxed worker + live APFS clonefileat + XNU token bind) */
    for (int i = 0; i < N_CREATE; i++) {
        sbx_pool_prepare_warm(&eng, i);
    }
    for (int i = 0; i < N_CREATE; i++) {
        sbx_create(&eng, SBX_CREATE_WARM, &samples_warm[i]);
    }
    for (int i = 0; i < N_CREATE; i++) {
        sbx_destroy(&eng, i);
    }
    bench_stats_t st_create_warm = compute_stats(samples_warm, N_CREATE);

    /* 3c. Hot Pre-Staged Create (pre-cloned APFS CoW + pre-sandboxed worker atomic checkout) */
    for (int i = 0; i < N_CREATE; i++) {
        sbx_pool_prepare_hot(&eng, i);
    }
    for (int i = 0; i < N_CREATE; i++) {
        sbx_create(&eng, SBX_CREATE_HOT, &samples_hot[i]);
    }
    for (int i = 0; i < N_CREATE; i++) {
        sbx_destroy(&eng, i);
    }
    bench_stats_t st_create_hot = compute_stats(samples_hot, N_CREATE);

    printf("[2/4] Container Creation Latency (Target to beat: 300,000 us / 300.00 ms, N=%d)\n", N_CREATE);
    printf("  %-36s | %9s | %9s | %9s | %9s | %12s\n",
           "Creation Mode", "Min (us)", "p50 (us)", "Mean (us)", "p99 (us)", "vs 300ms");
    printf("  -------------------------------------+-----------+-----------+-----------+-----------+-------------\n");
    printf("  %-36s | %9.2f | %9.2f | %9.2f | %9.2f | %11.1fx\n",
           "Reference Claim (300 ms)", 300000.0, 300000.0, 300000.0, 300000.0, 1.0);
    printf("  %-36s | %9.2f | %9.2f | %9.2f | %9.2f | %11.1fx\n",
           "Apple /usr/bin/sandbox-exec (CLI)",
           st_apple.min_us, st_apple.p50_us, st_apple.mean_us, st_apple.p99_us,
           300000.0 / st_apple.p50_us);
    printf("  %-36s | %9.2f | %9.2f | %9.2f | %9.2f | %11.1fx\n",
           "SBX Cold (CoW + fork + DFA apply)",
           st_create_cold.min_us, st_create_cold.p50_us, st_create_cold.mean_us, st_create_cold.p99_us,
           300000.0 / st_create_cold.p50_us);
    printf("  %-36s | %9.2f | %9.2f | %9.2f | %9.2f | %11.1fx\n",
           "SBX Warm Zygote (Live CoW + Token)",
           st_create_warm.min_us, st_create_warm.p50_us, st_create_warm.mean_us, st_create_warm.p99_us,
           300000.0 / st_create_warm.p50_us);
    printf("  %-36s | %9.3f | %9.3f | %9.3f | %9.3f | %11.1fx\n\n",
           "SBX Hot Pre-Staged (Pool Checkout)",
           st_create_hot.min_us, st_create_hot.p50_us, st_create_hot.mean_us, st_create_hot.p99_us,
           300000.0 / (st_create_hot.p50_us > 0.001 ? st_create_hot.p50_us : 0.001));

    /* 4. Measure Command Execution across all 3 execution engines */
    sbx_pool_prepare_warm(&eng, 0);
    int cid = sbx_create(&eng, SBX_CREATE_WARM, NULL);
    char out[256];
    int ec = 0;

    /* 4a. Direct In-Sandbox Execution (10,000 iterations) */
    const int N_EXEC_DIRECT = 10000;
    uint64_t *samples_exec_direct = calloc((size_t)N_EXEC_DIRECT, sizeof(uint64_t));
    /* Warmup */
    for (int i = 0; i < 50; i++) {
        sbx_exec(&eng, cid, SBX_EXEC_DIRECT, "echo hello_sandbox", out, sizeof(out), &ec, NULL);
    }
    for (int i = 0; i < N_EXEC_DIRECT; i++) {
        sbx_exec(&eng, cid, SBX_EXEC_DIRECT, "echo hello_sandbox", out, sizeof(out), &ec, &samples_exec_direct[i]);
    }
    bench_stats_t st_exec_direct = compute_stats(samples_exec_direct, N_EXEC_DIRECT);

    /* 4b. Persistent In-Sandbox /bin/sh Coprocess Execution (1,000 iterations) */
    const int N_EXEC_SHELL = 1000;
    uint64_t *samples_exec_shell = calloc((size_t)N_EXEC_SHELL, sizeof(uint64_t));
    /* Warmup (spawns persistent /bin/sh inside sandbox on first call) */
    for (int i = 0; i < 10; i++) {
        sbx_exec(&eng, cid, SBX_EXEC_SHELL, "echo $((6*7))_shell_ok", out, sizeof(out), &ec, NULL);
    }
    for (int i = 0; i < N_EXEC_SHELL; i++) {
        sbx_exec(&eng, cid, SBX_EXEC_SHELL, "echo $((6*7))_shell_ok", out, sizeof(out), &ec, &samples_exec_shell[i]);
    }
    bench_stats_t st_exec_shell = compute_stats(samples_exec_shell, N_EXEC_SHELL);

    /* 4c. Full External Mach-O Binary posix_spawn inside Sandbox (100 iterations) */
    const int N_EXEC_SPAWN = 100;
    uint64_t *samples_exec_spawn = calloc((size_t)N_EXEC_SPAWN, sizeof(uint64_t));
    for (int i = 0; i < N_EXEC_SPAWN; i++) {
        sbx_exec(&eng, cid, SBX_EXEC_SPAWN, "echo external_spawn_ok", out, sizeof(out), &ec, &samples_exec_spawn[i]);
    }
    bench_stats_t st_exec_spawn = compute_stats(samples_exec_spawn, N_EXEC_SPAWN);

    sbx_destroy(&eng, cid);

    printf("[3/4] Send Command / Exec Latency (Target to beat: 15,000 us / 15.00 ms)\n");
    printf("  %-36s | %9s | %9s | %9s | %9s | %12s\n",
           "Execution Engine", "Min (us)", "p50 (us)", "Mean (us)", "p99 (us)", "vs 15ms");
    printf("  -------------------------------------+-----------+-----------+-----------+-----------+-------------\n");
    printf("  %-36s | %9.2f | %9.2f | %9.2f | %9.2f | %11.1fx\n",
           "Reference Claim (15 ms)", 15000.0, 15000.0, 15000.0, 15000.0, 1.0);
    printf("  %-36s | %9.2f | %9.2f | %9.2f | %9.2f | %11.1fx\n",
           "SBX Full posix_spawn (/bin/sh -c)",
           st_exec_spawn.min_us, st_exec_spawn.p50_us, st_exec_spawn.mean_us, st_exec_spawn.p99_us,
           15000.0 / st_exec_spawn.p50_us);
    printf("  %-36s | %9.2f | %9.2f | %9.2f | %9.2f | %11.1fx\n",
           "SBX Persistent /bin/sh Coprocess",
           st_exec_shell.min_us, st_exec_shell.p50_us, st_exec_shell.mean_us, st_exec_shell.p99_us,
           15000.0 / st_exec_shell.p50_us);
    printf("  %-36s | %9.3f | %9.3f | %9.3f | %9.3f | %11.1fx\n\n",
           "SBX Direct In-Sandbox (SHM + ulock)",
           st_exec_direct.min_us, st_exec_direct.p50_us, st_exec_direct.mean_us, st_exec_direct.p99_us,
           15000.0 / st_exec_direct.p50_us);

    printf("[4/4] Summary vs Open-Source Target (300 ms create / 15 ms command)\n");
    printf("  * Create (Hot Pre-Staged) : %.4f ms (%.2f us)  -> %.0fx faster than 300 ms\n",
           st_create_hot.p50_us / 1000.0, st_create_hot.p50_us, 300000.0 / st_create_hot.p50_us);
    printf("  * Create (Warm On-Demand) : %.4f ms (%.2f us)  -> %.0fx faster than 300 ms\n",
           st_create_warm.p50_us / 1000.0, st_create_warm.p50_us, 300000.0 / st_create_warm.p50_us);
    printf("  * Create (Cold Fork+DFA)  : %.4f ms (%.2f us)  -> %.0fx faster than 300 ms\n",
           st_create_cold.p50_us / 1000.0, st_create_cold.p50_us, 300000.0 / st_create_cold.p50_us);
    printf("  * Command (Direct Builtin): %.5f ms (%.3f us) -> %.0fx faster than 15 ms\n",
           st_exec_direct.p50_us / 1000.0, st_exec_direct.p50_us, 15000.0 / st_exec_direct.p50_us);
    printf("  * Command (Persistent sh) : %.4f ms (%.2f us)  -> %.0fx faster than 15 ms\n",
           st_exec_shell.p50_us / 1000.0, st_exec_shell.p50_us, 15000.0 / st_exec_shell.p50_us);
    printf("  * Command (posix_spawn)   : %.4f ms (%.2f us)  -> %.1fx faster than 15 ms\n",
           st_exec_spawn.p50_us / 1000.0, st_exec_spawn.p50_us, 15000.0 / st_exec_spawn.p50_us);
    printf("========================================================================================\n");

    free(samples_cold);
    free(samples_warm);
    free(samples_hot);
    free(samples_exec_direct);
    free(samples_exec_shell);
    free(samples_exec_spawn);
    sbx_engine_close(&eng);
    return 0;
}

#ifdef SBX_STANDALONE_BENCH
int main(void) {
    return sbx_run_benchmarks();
}
#endif
