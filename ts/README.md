# sandbox-fast

Ultra-low-latency macOS sandbox container engine in pure C11 (`clang -O3 -flto -mcpu=native`), combining **APFS Copy-on-Write (`clonefileat`) rootfs isolation**, **pre-compiled XNU Kernel Mandatory Access Control (MAC) DFA bytecode (`sandbox_apply_bytecode`)**, **dynamic XNU capability tokens (`__mac_syscall("Sandbox", 5)`)**, and **16 KB hardware-page-isolated shared memory + Darwin `ulock` (`__ulock_wait` / `__ulock_wake`) IPC**.

## Single-Operation Latency & Throughput (`./sbx bench`)

| Operation | Mode | Min | Median (p50) | p99 | Rate (`ops / ms`) | vs Target (`300 ms` / `15 ms`) |
|---|---|---:|---:|---:|---:|---:|
| **Create** | Reference Claim | 300,000 µs | 300.000 ms (300,000 µs) | 300,000 µs | 0.0033 / ms | 1.0x |
| **Create** | Apple `/usr/bin/sandbox-exec` | 4,865.71 µs | 5.209 ms (5,208.62 µs) | 7,891.92 µs | 0.19 / ms | **57.6x faster** |
| **Create** | **SBX Cold** (Live APFS CoW + `fork` + DFA apply) | 320.75 µs | **0.508 ms (507.96 µs)** | 793.50 µs | **1.97 / ms** (3.12 peak) | **590.6x faster** |
| **Create** | **SBX Warm Zygote** (Live APFS CoW + XNU Token) | 85.08 µs | **0.104 ms (104.00 µs)** | 163.62 µs | **9.62 / ms** (11.75 peak) | **2,884.6x faster** |
| **Create** | **SBX Hot Pre-Staged** (Pool Checkout) | 0.041 µs | **0.00054 ms (0.542 µs)** | 1.000 µs | **1,845 / ms** (24,390 peak) | **553,505.5x faster** |
| **Command** | Reference Claim | 15,000 µs | 15.000 ms (15,000 µs) | 15,000 µs | 0.067 / ms | 1.0x |
| **Command** | **SBX Full `posix_spawn`** (External Mach-O binary) | 615.21 µs | **0.646 ms (646.33 µs)** | 831.67 µs | **1.55 / ms** | **23.2x faster** |
| **Command** | **SBX Persistent `/bin/sh`** (In-sandbox coprocess) | 20.08 µs | **0.025 ms (25.00 µs)** | 37.75 µs | **40.0 / ms** | **600.0x faster** |
| **Command** | **SBX Direct In-Sandbox** (SHM + Darwin `ulock`) | 0.500 µs | **0.00058 ms (0.584 µs)** | 0.709 µs | **1,712 / ms** | **25,684.9x faster** |

## 1,000-Container Creation + `"hello world"` Benchmark (`./test_1000.sh`)

| Mode (1,000 Containers + `"hello world"` + Teardown) | Total Create (1,000x) | Total Exec (1,000x) | Total Teardown (1,000x) | Total Wall-Clock Time | Full Lifecycle Rate | vs 315s Ref |
|---|---:|---:|---:|---:|---:|---:|
| **Reference Claim** (`300ms + 15ms` × 1,000) | 300,000.00 ms | 15,000.00 ms | — | **315,000.00 ms (315.00 s)** | 0.0032 / ms (`3.2/s`) | 1.0x |
| **`./test_1000.sh cold`** (1,000 OS `fork` + CoW + DFA) | 478.69 ms (`478.7 µs`/ea) | 6.99 ms (`6.99 µs`/ea) | 364.86 ms | **852.94 ms (0.853 s)** | **1.17 / ms** (`1,172/s`) | **369.3x faster** |
| **`./test_1000.sh warm`** (1,000 APFS CoW + XNU Tokens) | 118.65 ms (`118.7 µs`/ea) | 7.11 ms (`7.11 µs`/ea) | 269.48 ms | **395.42 ms (0.395 s)** | **2.53 / ms** (`2,529/s`) | **796.6x faster** |
| **`./test_1000.sh hot`** (Pre-Staged Pool Checkout) | 0.01 ms (`0.01 µs`/ea) | 0.67 ms (`0.67 µs`/ea) | 0.01 ms | **0.76 ms (0.00076 s)** | **1,315.7 / ms** (`1.32M/s`) | **414,450.8x faster** |

## Local Drive Mounting & Agent Execution Timings (`./demo_agent.sh`)

| Agent / Mount Operation | Command | Latency |
|---|---|---:|
| **Mount Local Drive (Read-Write)** | `./sbx mount --rw <id> <host_dir> workspace` | **62.04 µs (0.062 ms)** |
| **Mount Local Drive (Read-Only)** | `./sbx mount --ro <id> <host_dir> workspace` | **~60.00 µs (0.060 ms)** |
| **Mount Local Drive (APFS CoW Snapshot)** | `./sbx mount --cow <id> <host_dir> workspace_cow` | **109.75 µs (0.110 ms)** |
| **Agent `ls workspace` / `cat TASK.md` (CLI IPC)** | `./sbx exec <id> ls workspace` | **22.62 – 32.46 µs** |
| **Kernel Escape Block (`EPERM`)** | `./sbx exec <id> cat /Users/chris/AGENTS.md` | **31.62 – 36.58 µs** |

## Quick Reference & Commands

```sh
make                        # Build ./sbx, ./bench, and ./test_1000
./sbx bench                 # Run full latency & 6-point isolation benchmark suite
./sbx verify                # Run 6-point XNU MAC + APFS CoW security verification
./test_1000.sh [warm|hot|cold]  # Run 1,000-container "hello world" benchmark
./demo_agent.sh             # Run autonomous coding agent + mapped local drive demo

# Interactive CLI
./sbx create [hot|warm|cold]
./sbx mount [--rw|--ro|--cow] <id> <host_dir> [mount_name]
./sbx exec [--direct|--shell|--spawn] <id> <cmd...>
./sbx run <cmd...>
./sbx ls
./sbx rm <id>
./sbx daemon <start|stop|status>
```
