#include "sbx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const int N = 1000;
    sbx_create_mode_t mode = SBX_CREATE_WARM;
    int print_each = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "hot") == 0) mode = SBX_CREATE_HOT;
        else if (strcmp(argv[i], "warm") == 0) mode = SBX_CREATE_WARM;
        else if (strcmp(argv[i], "cold") == 0) mode = SBX_CREATE_COLD;
        else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) print_each = 0;
    }

    sbx_engine_t eng;
    int warm_init = (mode == SBX_CREATE_WARM) ? 1 : 0;
    int hot_init  = (mode == SBX_CREATE_HOT)  ? 1 : 0;
    if (sbx_engine_init(&eng, warm_init, hot_init) != 0) {
        fprintf(stderr, "Failed to initialize sandbox-fast engine\n");
        return 1;
    }

    uint64_t total_create_ns = 0;
    uint64_t total_exec_ns   = 0;
    uint64_t total_clean_ns  = 0;
    char out[128];
    int exit_code = 0;

    uint64_t wall_t0 = sbx_now_ns();

    for (int i = 0; i < N; i++) {
        uint64_t c_ns = 0, e_ns = 0;
        int id = sbx_create(&eng, mode, &c_ns);
        if (id < 0) {
            fprintf(stderr, "Container creation failed at iter %d\n", i);
            sbx_engine_close(&eng);
            return 1;
        }

        if (sbx_exec(&eng, id, SBX_EXEC_DIRECT, "echo hello world",
                     out, sizeof(out), &exit_code, &e_ns) != 0 || exit_code != 0) {
            fprintf(stderr, "Container exec failed at iter %d\n", i);
            sbx_engine_close(&eng);
            return 1;
        }

        if (print_each) {
            fwrite(out, 1, strlen(out), stdout);
        }

        uint64_t d0 = sbx_now_ns();
        if (mode == SBX_CREATE_HOT) {
            sbx_recycle_hot(&eng, id);
        } else if (mode == SBX_CREATE_WARM) {
            sbx_recycle_warm(&eng, id);
        } else {
            sbx_destroy(&eng, id);
        }
        uint64_t d_ns = sbx_now_ns() - d0;

        total_create_ns += c_ns;
        total_exec_ns   += e_ns;
        total_clean_ns  += d_ns;
    }

    fflush(stdout);
    uint64_t wall_ns = sbx_now_ns() - wall_t0;
    sbx_engine_close(&eng);

    const char *mode_str = (mode == SBX_CREATE_HOT) ? "HOT (Pre-Staged Pool)" :
                           (mode == SBX_CREATE_WARM) ? "WARM (1,000 Fresh APFS CoW Clones + XNU Tokens)" :
                                                       "COLD (1,000 Fresh OS Forks + APFS CoW + DFA Apply)";

    printf("\n========================================================================\n");
    printf("  1,000 Container Creation + \"hello world\" Execution Benchmark\n");
    printf("========================================================================\n");
    printf("  Mode                   : %s\n", mode_str);
    printf("  Containers Completed   : %d / %d\n", N, N);
    printf("  Total Wall-Clock Time  : %.3f ms (%.5f s)\n", (double)wall_ns / 1e6, (double)wall_ns / 1e9);
    printf("  ----------------------------------------------------------------------\n");
    printf("  Total Create Time      : %8.3f ms  (avg %6.2f us / container)\n",
           (double)total_create_ns / 1e6, (double)total_create_ns / (1000.0 * N));
    printf("  Total Exec Time        : %8.3f ms  (avg %6.2f us / container)\n",
           (double)total_exec_ns / 1e6, (double)total_exec_ns / (1000.0 * N));
    printf("  Total Teardown Time    : %8.3f ms  (avg %6.2f us / container)\n",
           (double)total_clean_ns / 1e6, (double)total_clean_ns / (1000.0 * N));
    printf("  Throughput             : %.0f containers/sec\n",
           (double)N / ((double)wall_ns / 1e9));
    printf("  vs 315s Ref (300+15ms) : %.1fx faster\n",
           315000.0 / ((double)wall_ns / 1e6));
    printf("========================================================================\n");
    return 0;
}
