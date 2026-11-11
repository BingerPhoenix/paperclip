import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { runChildProcess, getLiveProcessAccounting, getRetainedProcessEvidence, forgetRetainedProcessEvidence, processAdmissionHolds } from "./server-utils.js";

describe("official-run accounting retention", () => {
  it("retains normal-exit history and never resets a repeated official run", async () => {
    const runId = "owned-nonmodel-retention-fixture";
    const path = realpathSync(process.execPath);
    const options = {
      cwd: process.cwd(), env: {}, timeoutSec: 3, graceSec: 1, onLog: async () => {}, stdin: "finish",
      onSpawn: async () => {
        // Establish the positive fixture's capture precondition before allowing
        // natural exit. A missed short-lived identity must still remain unknown.
        const deadline = Date.now() + 1000;
        while (!getLiveProcessAccounting(runId)?.root && Date.now() < deadline) {
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        expect(getLiveProcessAccounting(runId)?.root).not.toBeNull();
      },
      processAccounting: { sourceCommit: "a".repeat(40), contractSha256: "b".repeat(64), expectedNativeStarts: 0,
        pins: [{ id: "owned-node", path, sha256: createHash("sha256").update(readFileSync(path)).digest("hex"), classification: "node_helper" as const }] },
    };
    try {
      const first = await runChildProcess(runId, process.execPath, ["-e", "const hard=setTimeout(()=>process.exit(2),1500);process.stdin.once('data',()=>{process.stdout.write('retained');clearTimeout(hard);setTimeout(()=>{},50)});"], options);
      expect(first.exitCode).toBe(0);
      expect(first.processCleanup?.state, JSON.stringify({ cleanupErrors: first.processCleanup?.errors,
        accountingErrors: first.processCleanup?.accounting?.errors,
        observations: first.processCleanup?.accounting?.observations.filter((row) => row.owned) })).toBe("observed_gone");
      const retained = getLiveProcessAccounting(runId);
      expect(retained?.state).toBe("bounded_observed");
      expect(retained?.observations.some((row) => row.pid === first.pid)).toBe(true);
      await expect(runChildProcess(runId, process.execPath, ["-e", "setTimeout(()=>{},180)"], options)).rejects.toThrow("cannot admit another process");
      const repeated = getRetainedProcessEvidence(runId);
      expect(repeated?.accounting.errors).toContain("additional_process_admission_rejected");
      expect(repeated?.accounting.state).toBe("unknown");
      expect(repeated?.accounting.observations.some((row) => row.pid === first.pid)).toBe(true);
    } finally { forgetRetainedProcessEvidence(runId); processAdmissionHolds.delete(runId); }
    expect(getLiveProcessAccounting(runId)).toBeNull();
  }, 6000);
});
