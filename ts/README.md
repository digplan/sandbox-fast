# sandbox-fast

Minimal macOS container sandbox written in C11. It uses APFS copy-on-write directory clones (`clonefileat`), precompiled XNU Seatbelt bytecode (`sandbox_apply_bytecode`), kernel capability tokens, and shared memory with Darwin `ulock` for IPC.

## Quick start

Run the 1,000-container benchmark directly via npx:

```sh
npx fast-container-for-ant
```

Or build from source:

```sh
make
./sbx bench
./sbx verify
./test_1000.sh
./demo_agent.sh
```

## Benchmarks

Measured on Apple Silicon (macOS 27.0 / Darwin 27.0.0) against a reference target of 300 ms container creation and 15 ms command execution.

### Single operation latency

| Operation | Mode | Min (us) | Median p50 (us) | p99 (us) | Rate (ops/ms) | Speedup vs target |
|---|---|---:|---:|---:|---:|---:|
| Create | Reference target (300 ms) | 300,000.00 | 300,000.00 | 300,000.00 | 0.0033 | 1.0x |
| Create | Apple sandbox-exec CLI | 4,865.71 | 5,208.62 | 7,891.92 | 0.19 | 57.6x |
| Create | Cold (APFS CoW + fork + DFA) | 320.75 | 507.96 | 793.50 | 1.97 | 590.6x |
| Create | Warm zygote (live CoW + token) | 85.08 | 104.00 | 163.62 | 9.62 | 2,884.6x |
| Create | Hot pre-staged (pool checkout) | 0.041 | 0.542 | 1.000 | 1,845.0 | 553,505.5x |
| Command | Reference target (15 ms) | 15,000.00 | 15,000.00 | 15,000.00 | 0.067 | 1.0x |
| Command | Full posix_spawn (external binary) | 615.21 | 646.33 | 831.67 | 1.55 | 23.2x |
| Command | Persistent /bin/sh coprocess | 20.08 | 25.00 | 37.75 | 40.0 | 600.0x |
| Command | Direct builtin (SHM + ulock) | 0.500 | 0.584 | 0.709 | 1,712.3 | 25,684.9x |

### 1,000-container benchmark

Creates 1,000 containers sequentially, runs `echo "hello world"` inside each one, prints the output, and tears the container down.

| Mode | Create total | Exec total | Teardown total | Wall time | Rate (containers/ms) | Speedup vs 315s |
|---|---:|---:|---:|---:|---:|---:|
| Reference (315 ms x 1,000) | 300,000.00 ms | 15,000.00 ms | - | 315,000.00 ms (315.00 s) | 0.0032 | 1.0x |
| Cold (1,000 forks + CoW) | 478.69 ms | 6.99 ms | 364.86 ms | 852.94 ms (0.853 s) | 1.17 | 369.3x |
| Warm (1,000 CoW + tokens) | 118.65 ms | 7.11 ms | 269.48 ms | 395.42 ms (0.395 s) | 2.53 | 796.6x |
| Hot (pre-staged pool) | 0.01 ms | 0.67 ms | 0.01 ms | 0.76 ms (0.00076 s) | 1,315.7 | 414,450.8x |

### Local drive mount and agent operations

| Operation | Command | Time (us) |
|---|---|---:|
| Mount local folder (read-write) | `./sbx mount --rw <id> <dir> workspace` | 62.04 |
| Mount local folder (read-only) | `./sbx mount --ro <id> <dir> workspace` | 60.00 |
| Mount local folder (APFS CoW clone) | `./sbx mount --cow <id> <dir> workspace_cow` | 109.75 |
| Agent directory list / file read | `./sbx exec <id> ls workspace` | 22.62 - 32.46 |
| Kernel block on host file read (EPERM) | `./sbx exec <id> cat /Users/chris/AGENTS.md` | 31.62 - 36.58 |

## How it works

1. Precompiled sandbox bytecode: `sandbox_init()` normally runs a TinyScheme parser on every invocation (~11.7 ms). `sbx` compiles the profile once with `sandbox_compile_string()`, caches the DFA bytecode to `/private/tmp/sbx-fast/profile.dfa`, and loads it into the kernel with `sandbox_apply_bytecode()` in ~95 us.
2. Dynamic capability tokens: Worker processes enter the XNU sandbox before a container directory is assigned. On creation, the controller clones `/private/tmp/sbx-fast/base_rootfs` with `clonefileat()` and issues a `com.apple.app-sandbox.read-write` token directly into shared memory via `__mac_syscall("Sandbox", 5)`.
3. Page-isolated shared memory IPC: Each container uses a single 16 KB page (`SBX_PAGE_SIZE = 16384`). Before applying the sandbox profile, each worker unmaps the control page and all other container slots so its page tables only map its own IPC buffer.

## CLI usage

```sh
./sbx create [hot|warm|cold]
./sbx mount [--rw|--ro|--cow] <id> <host_dir> [mount_name]
./sbx exec [--direct|--shell|--spawn] <id> <cmd...>
./sbx run <cmd...>
./sbx ls
./sbx rm <id>
./sbx daemon <start|stop|status>
```
