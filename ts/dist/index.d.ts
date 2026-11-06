export type CreateMode = "hot" | "warm" | "cold";
export type ExecMode = "auto" | "direct" | "shell" | "spawn";
export type MountMode = "rw" | "ro" | "cow";
export interface Run1000Options {
    readonly mode?: CreateMode;
    readonly quiet?: boolean;
    readonly inheritStdio?: boolean;
}
export interface Run1000Result {
    readonly mode: CreateMode;
    readonly exitCode: number;
    readonly stdout: string;
    readonly stderr: string;
}
export declare function ensureNativeBinaries(): {
    readonly test1000Bin: string;
    readonly sbxBin: string;
};
export declare function stopDaemonQuietly(sbxBin: string): void;
export declare function run1000Containers(options?: Run1000Options): Promise<Run1000Result>;
export declare function runSbxCommand(args: readonly string[]): number;
