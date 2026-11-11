import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  processCleanupHoldMetadata, processCleanupEvidenceSha256, readProcessCleanupHold,
  releaseProcessCleanupHoldRequestSchema, validateReviewedProcessCleanup,
} from "../services/process-cleanup-hold.js";

function fixture() {
  const runId = randomUUID();
  const identity = { pid: 2147483646, start: "fixture-start", parent: 1,
    executable: "/declared/python", classification: "python_helper" };
  const cleanup = {
    scope: "sampled_pid_start_identity", state: "observed_gone", observed: 1,
    remaining: 0, errors: [], capturedIdentities: [identity],
    accounting: { scope: "bounded_sampled_process_accounting", state: "bounded_observed",
      runId, root: { pid: identity.pid, start: identity.start }, baselineDigest: "a".repeat(64),
      baselineObservedAt: "2026-11-10T21:00:00.000Z", sourceCommit: "b".repeat(40),
      contractSha256: "c".repeat(64), expectedNativeStarts: 0, modelStartCount: 0, errors: [] },
  };
  return { runId, cleanup, input: { cleanup, expectedRunId: runId,
    reviewedCleanupEvidenceSha256: processCleanupEvidenceSha256(cleanup),
    processPid: identity.pid, adapterType: "process", snapshot: [] } };
}

describe("identified cleanup review", () => {
  it("creates a new hold generation even for the same run", () => {
    const runId = randomUUID();
    const a = readProcessCleanupHold(processCleanupHoldMetadata({ retained: true }, runId, "review"));
    const b = readProcessCleanupHold(processCleanupHoldMetadata({}, runId, "review"));
    expect(a.holdId).not.toBe(runId); expect(a.holdId).not.toBe(b.holdId);
    expect(() => readProcessCleanupHold({ processCleanupHold: { runId } })).toThrow();
  });
  it("canonicalizes full official JSON independently of object insertion order", () => {
    expect(processCleanupEvidenceSha256({ z: [3, { y: 2, x: 1 }], a: true }))
      .toBe(processCleanupEvidenceSha256({ a: true, z: [3, { x: 1, y: 2 }] }));
    expect(() => processCleanupEvidenceSha256({ missing: undefined })).toThrow();
    let deep: unknown = null; for (let i = 0; i < 34; i++) deep = { deep };
    expect(() => processCleanupEvidenceSha256(deep)).toThrow();
  });
  it("requires the distinct hold/run and explicit reviewed hash without extra claims", () => {
    const request = { expectedHoldId: randomUUID(), expectedRunId: randomUUID(),
      reviewedCleanupEvidenceSha256: "a".repeat(64), reviewNote: "Reviewed captured identities" };
    expect(releaseProcessCleanupHoldRequestSchema.safeParse(request).success).toBe(true);
    expect(releaseProcessCleanupHoldRequestSchema.safeParse({ ...request, terminated: true }).success).toBe(false);
    expect(releaseProcessCleanupHoldRequestSchema.safeParse({ ...request, reviewNote: " " }).success).toBe(false);
  });
  it("accepts only current official evidence and rejects a caller's unmatched digest", () => {
    const { input } = fixture(); expect(() => validateReviewedProcessCleanup(input)).not.toThrow();
    expect(() => validateReviewedProcessCleanup({ ...input, reviewedCleanupEvidenceSha256: "d".repeat(64) })).toThrow();
  });
  it("gates known live identity while distinguishing PID reuse and stopped zombies", () => {
    const { input } = fixture(); const id = input.cleanup.capturedIdentities[0]!;
    expect(() => validateReviewedProcessCleanup({ ...input, snapshot: [{ ...id, state: "S" }] })).toThrow();
    expect(() => validateReviewedProcessCleanup({ ...input, snapshot: [{ ...id, start: "new-process", state: "S" }] })).not.toThrow();
    expect(() => validateReviewedProcessCleanup({ ...input, snapshot: [{ ...id, state: "Z" }] })).not.toThrow();
  });
  it("does not release unresolved cleanup even after old identities disappear", () => {
    const { cleanup, input } = fixture(); cleanup.state = "unknown";
    expect(() => validateReviewedProcessCleanup({ ...input, reviewedCleanupEvidenceSha256: processCleanupEvidenceSha256(cleanup) })).toThrow();
  });
  it("rejects forged official run/root binding and unknown accounting", () => {
    for (const change of ["run", "root", "accounting", "class"]) {
      const { cleanup, input } = fixture();
      if (change === "run") cleanup.accounting.runId = randomUUID();
      if (change === "root") cleanup.accounting.root.pid--;
      if (change === "accounting") cleanup.accounting.state = "unknown";
      if (change === "class") cleanup.capturedIdentities[0]!.classification = "unknown";
      expect(() => validateReviewedProcessCleanup({ ...input, reviewedCleanupEvidenceSha256: processCleanupEvidenceSha256(cleanup) })).toThrow();
    }
  });
});
