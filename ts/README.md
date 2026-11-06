# sandbox-fast

Minimal C11 container sandbox for macOS (APFS copy-on-write + precompiled XNU Seatbelt bytecode + shared memory IPC).

## Benchmarks

| Metric | sandbox-fast | Reference target | Speedup |
|---|---:|---:|---:|
| Container create (hot pool) | 0.54 us (0.00054 ms) | 300 ms | 553,505x |
| Container create (warm APFS CoW) | 104.00 us (0.104 ms) | 300 ms | 2,885x |
| Command exec (direct SHM) | 0.58 us (0.00058 ms) | 15 ms | 25,685x |
| Command exec (persistent sh) | 25.00 us (0.025 ms) | 15 ms | 600x |
| Local drive mount (read-write) | 62.04 us (0.062 ms) | - | - |
| 1,000 containers + "hello world" (hot) | 0.76 ms total (1,316/ms) | 315,000 ms | 414,451x |
| 1,000 containers + "hello world" (warm CoW) | 395.42 ms total (2.53/ms) | 315,000 ms | 797x |

## Run

```sh
npx fast-container-for-ant
npx fast-container-for-ant hot
```

## Build from source

```sh
make
./sbx bench
./test_1000.sh
./demo_agent.sh
```

## CLI

```sh
./sbx create [hot|warm|cold]
./sbx mount [--rw|--ro|--cow] <id> <host_dir> [mount_name]
./sbx exec [--direct|--shell|--spawn] <id> <cmd...>
./sbx run <cmd...>
./sbx ls
./sbx rm <id>
```
