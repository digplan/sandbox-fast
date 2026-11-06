#!/usr/bin/env node
import {
  type CreateMode,
  ensureNativeBinaries,
  run1000Containers,
  runSbxCommand,
} from "./index.js";

function isCreateMode(val: string): val is CreateMode {
  return val === "hot" || val === "warm" || val === "cold";
}

function printHelp(): void {
  console.log(`Usage: npx fast-container-for-ant [mode|command] [options]

1,000-Container "hello world" Benchmark (Default):
  npx fast-container-for-ant                Run 1,000 WARM containers (fresh APFS CoW + XNU token)
  npx fast-container-for-ant hot            Run 1,000 HOT pre-staged containers (~0.76 ms total)
  npx fast-container-for-ant warm           Run 1,000 WARM containers (~395 ms total)
  npx fast-container-for-ant cold           Run 1,000 COLD containers (1,000 OS forks, ~850 ms total)
  npx fast-container-for-ant all            Run HOT, WARM, and COLD 1,000-container benchmarks
  npx fast-container-for-ant [mode] --quiet Suppress individual "hello world" lines, show summary only

Sandbox Engine Subcommands:
  npx fast-container-for-ant bench          Run full p50/p99 latency & 6-point isolation suite
  npx fast-container-for-ant verify         Run 6-point XNU kernel MAC & APFS CoW isolation check
  npx fast-container-for-ant run <cmd...>   One-shot create + exec + destroy container
  npx fast-container-for-ant create [mode]  Create a persistent container
  npx fast-container-for-ant mount <id> <host_dir> [mount_name]
  npx fast-container-for-ant exec <id> <cmd...>
  npx fast-container-for-ant ls | rm <id> | daemon <start|stop|status>
`);
}

async function main(): Promise<number> {
  const args: string[] = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    return 0;
  }

  if (args.includes("--build-only")) {
    ensureNativeBinaries();
    return 0;
  }

  const quiet: boolean = args.includes("--quiet") || args.includes("-q");
  const filtered: string[] = args.filter((a) => a !== "--quiet" && a !== "-q");
  const first: string | undefined = filtered[0];

  if (first === undefined || isCreateMode(first)) {
    const mode: CreateMode = first ?? "warm";
    const res = await run1000Containers({ mode, quiet, inheritStdio: true });
    return res.exitCode;
  }

  if (first === "all") {
    for (const mode of ["hot", "warm", "cold"] as const) {
      const res = await run1000Containers({ mode, quiet: true, inheritStdio: true });
      if (res.exitCode !== 0) {
        return res.exitCode;
      }
    }
    return 0;
  }

  return runSbxCommand(args);
}

main()
  .then((code: number) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`fast-container-for-ant error: ${msg}`);
    process.exitCode = 1;
  });
