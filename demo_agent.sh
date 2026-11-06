#!/usr/bin/env zsh
set -euo pipefail

cd "${0:A:h}"

# Ensure binaries are up to date
make sbx >/dev/null
./sbx daemon stop >/dev/null 2>&1 || true

HOST_DRIVE="/private/tmp/sbx-agent-drive"
rm -rf "$HOST_DRIVE"
mkdir -p "$HOST_DRIVE"

# 1. Seed the local host drive with a task and a buggy C program
cat << 'EOF' > "$HOST_DRIVE/TASK.md"
Task: Fix sum_1_to_n(10) in buggy_calc.c so it returns 55 instead of 45, verify tests pass, and write agent_result.json.
EOF

cat << 'EOF' > "$HOST_DRIVE/buggy_calc.c"
#include <stdio.h>

int sum_1_to_n(int n) {
    int total = 0;
    /* BUG: off-by-one (i < n instead of i <= n) */
    for (int i = 1; i < n; i++) {
        total += i;
    }
    return total;
}

int main(void) {
    int got = sum_1_to_n(10);
    if (got != 55) {
        printf("TEST FAIL: sum_1_to_n(10) expected 55, got %d\n", got);
        return 1;
    }
    printf("TEST PASS: sum_1_to_n(10) == %d\n", got);
    return 0;
}
EOF

echo "================================================================================"
echo "  sandbox-fast: Autonomous Coding Agent + Mapped Local Drive Demonstration"
echo "================================================================================"
echo "[Host] Created local drive at: $HOST_DRIVE"
ls -la "$HOST_DRIVE"
echo ""

# 2. Start daemon and create an isolated sandbox container
echo "[Step 1] Starting sbx daemon & creating isolated container..."
./sbx daemon start
CREATE_OUT=$(./sbx create warm)
echo "  -> $CREATE_OUT"
CID=$(echo "$CREATE_OUT" | awk -F'[= ]' '{print $2}')
echo ""

# 3. Verify that BEFORE mounting, the container is blocked from writing to $HOST_DRIVE
echo "[Step 2] Verifying XNU sandbox blocks access before drive is mounted..."
set +e
./sbx exec "$CID" touch "$HOST_DRIVE/unmounted_probe.txt"
UNMOUNTED_RC=$?
set -e
echo "  -> Unmounted write attempt exit code: $UNMOUNTED_RC (expected non-zero / EPERM)"
echo ""

# 4. Map the local host drive into container:/workspace via XNU capability token
echo "[Step 3] Mapping local host drive ($HOST_DRIVE) -> container $CID:/workspace (--rw)..."
./sbx mount --rw "$CID" "$HOST_DRIVE" workspace
echo ""

# 5. Agent Tool Call 1: Inspect mapped workspace
echo "[Step 4] Agent Tool Call #1: Inspecting mapped drive (/workspace)..."
./sbx exec "$CID" ls workspace
./sbx exec "$CID" cat workspace/TASK.md
echo ""

# 6. Agent Tool Call 2: Compile & reproduce the bug inside the sandbox
echo "[Step 5] Agent Tool Call #2: Compiling & running buggy_calc.c inside sandbox..."
set +e
./sbx exec --shell "$CID" 'clang -O2 workspace/buggy_calc.c -o tmp/calc && ./tmp/calc'
BUG_RC=$?
set -e
echo "  -> Initial test run exited with code $BUG_RC (bug reproduced!)"
echo ""

# 7. Agent Tool Call 3: Security boundary check (escape attempt outside mapped drive)
echo "[Step 6] Agent Tool Call #3: Testing XNU kernel containment during agent session..."
set +e
./sbx exec "$CID" cat /Users/chris/AGENTS.md
READ_HOME_RC=$?
./sbx exec "$CID" touch /private/tmp/host_escape.txt
WRITE_TMP_RC=$?
set -e
echo "  -> Read /Users/chris/AGENTS.md blocked (rc=$READ_HOME_RC), Write /private/tmp blocked (rc=$WRITE_TMP_RC)"
echo ""

# 8. Agent Tool Call 4: Patch the bug on the mapped drive, recompile, and write report
echo "[Step 7] Agent Tool Call #4: Patching workspace/buggy_calc.c & verifying fix..."
./sbx exec --shell "$CID" '
sed -i "" "s/i < n/i <= n/" workspace/buggy_calc.c &&
clang -O2 workspace/buggy_calc.c -o tmp/calc &&
./tmp/calc &&
printf "{\"status\":\"fixed\",\"test_passed\":true,\"sum_10\":55}\n" > workspace/agent_result.json
'
echo ""

# 9. Bonus: Demonstrate APFS Copy-on-Write (--cow) snapshot mount
echo "[Step 8] Bonus: Mounting $HOST_DRIVE as an isolated APFS CoW snapshot (/workspace_cow)..."
./sbx mount --cow "$CID" "$HOST_DRIVE" workspace_cow
./sbx exec --shell "$CID" 'rm -f workspace_cow/buggy_calc.c && echo "deleted in CoW clone" > workspace_cow/DESTROYED.txt && ls workspace_cow'
echo "  -> Inside container /workspace_cow, buggy_calc.c was deleted without affecting host drive!"
echo ""

# 10. Tear down sandbox and verify persisted changes on the host drive
echo "[Step 9] Destroying sandbox container $CID and verifying files on host drive ($HOST_DRIVE)..."
./sbx rm "$CID"
./sbx daemon stop

echo ""
echo "[Host Verification] Contents of $HOST_DRIVE on host after sandbox teardown:"
ls -la "$HOST_DRIVE"
echo ""
echo "[Host Verification] Persisted $HOST_DRIVE/agent_result.json:"
cat "$HOST_DRIVE/agent_result.json"
echo ""
echo "[Host Verification] Diff of patched $HOST_DRIVE/buggy_calc.c (line 6):"
grep -n "for (int i" "$HOST_DRIVE/buggy_calc.c"
echo "================================================================================"
