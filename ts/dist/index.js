import { spawnSync, spawn } from "node:child_process";
import { existsSync, accessSync, constants } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const NATIVE_DIR = join(PKG_ROOT, "native");
function isExecutable(binPath) {
    if (!existsSync(binPath)) {
        return false;
    }
    try {
        accessSync(binPath, constants.X_OK);
        return true;
    }
    catch {
        return false;
    }
}
export function ensureNativeBinaries() {
    if (process.platform !== "darwin") {
        throw new Error(`fast-container-for-ant requires macOS (darwin); detected platform '${process.platform}'`);
    }
    const test1000Bin = join(NATIVE_DIR, "test_1000");
    const sbxBin = join(NATIVE_DIR, "sbx");
    if (!isExecutable(test1000Bin)) {
        const res = spawnSync("clang", [
            "-std=c11",
            "-O3",
            "-flto",
            "-mcpu=native",
            "-Wno-deprecated-declarations",
            join(NATIVE_DIR, "test_1000.c"),
            join(NATIVE_DIR, "sbx.c"),
            "-lsandbox",
            "-o",
            test1000Bin,
        ], { stdio: "inherit" });
        if (res.status !== 0) {
            throw new Error(`Failed to compile native test_1000 binary (exit=${String(res.status)})`);
        }
    }
    if (!isExecutable(sbxBin)) {
        const res = spawnSync("clang", [
            "-std=c11",
            "-O3",
            "-flto",
            "-mcpu=native",
            "-Wno-deprecated-declarations",
            join(NATIVE_DIR, "main.c"),
            join(NATIVE_DIR, "sbx.c"),
            join(NATIVE_DIR, "bench.c"),
            "-lsandbox",
            "-o",
            sbxBin,
        ], { stdio: "inherit" });
        if (res.status !== 0) {
            throw new Error(`Failed to compile native sbx binary (exit=${String(res.status)})`);
        }
    }
    return { test1000Bin, sbxBin };
}
export function stopDaemonQuietly(sbxBin) {
    spawnSync(sbxBin, ["daemon", "stop"], { stdio: "ignore" });
}
export async function run1000Containers(options = {}) {
    const { test1000Bin, sbxBin } = ensureNativeBinaries();
    stopDaemonQuietly(sbxBin);
    const mode = options.mode ?? "warm";
    const args = [mode];
    if (options.quiet === true) {
        args.push("--quiet");
    }
    if (options.inheritStdio !== false) {
        const res = spawnSync(test1000Bin, args, { stdio: "inherit" });
        return {
            mode,
            exitCode: res.status ?? 1,
            stdout: "",
            stderr: "",
        };
    }
    return new Promise((resolve, reject) => {
        const child = spawn(test1000Bin, args, { stdio: ["ignore", "pipe", "pipe"] });
        const outChunks = [];
        const errChunks = [];
        child.stdout.on("data", (chunk) => outChunks.push(chunk));
        child.stderr.on("data", (chunk) => errChunks.push(chunk));
        child.on("error", (err) => reject(err));
        child.on("close", (code) => {
            resolve({
                mode,
                exitCode: code ?? 1,
                stdout: Buffer.concat(outChunks).toString("utf8"),
                stderr: Buffer.concat(errChunks).toString("utf8"),
            });
        });
    });
}
export function runSbxCommand(args) {
    const { sbxBin } = ensureNativeBinaries();
    const res = spawnSync(sbxBin, [...args], { stdio: "inherit" });
    return res.status ?? 1;
}
