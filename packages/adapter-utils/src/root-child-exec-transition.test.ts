import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { createProcessAccounting, type ProcessAccountingOptions } from "./process-accounting.js";
import { parseProcessAccountingPolicy } from "./server-utils.js";
import type { ProcessIdentity } from "./process-containment.js";

// Substitute artifact files and deterministic snapshots; no model executable runs.
describe("explicit bounded root-child exec classification", () => {
  let directory: string, native: string, helper: string, now: number, options: ProcessAccountingOptions;
  const at = (ms: number) => new Date(Date.UTC(2026, 10, 11) + ms).toISOString();
  const row = (pid: number, parent: number, executable: string | null, start = `start-${pid}`): ProcessIdentity =>
    ({ pid, parent, executable, start, state: "S" });
  beforeEach(() => {
    now = 0; vi.spyOn(performance, "now").mockImplementation(() => now);
    directory = mkdtempSync(join(tmpdir(), "owned-helper-transition-"));
    native = join(directory, "synthetic-parent"); helper = join(directory, "synthetic-helper");
    writeFileSync(native, "nonmodel native-image substitute"); writeFileSync(helper, "nonmodel helper-image substitute");
    options = { baseline: { observedAt: at(0), processes: [] }, sourceCommit: "a".repeat(40),
      contractSha256: "b".repeat(64), expectedNativeStarts: 1,
      pins: [{ id: "native", path: native, classification: "native_model" },
        { id: "helper", path: helper, classification: "declared_helper" }].map((p) => ({ ...p,
        classification: p.classification as "native_model" | "declared_helper",
        sha256: createHash("sha256").update(readFileSync(p.path)).digest("hex") })),
      rootChildExecTransition: { parentPinId: "native", helperPinId: "helper", deadlineMs: 250,
        sourceCommit: "c".repeat(40), sourceEvidenceSha256: "d".repeat(64) } };
  });
  afterEach(() => { vi.restoreAllMocks(); rmSync(directory, { recursive: true, force: true }); });
  function observer(policy = options) {
    const a = createProcessAccounting(policy); a.bindRoot({ runId: "owned-simulation", rootPid: 100 });
    now = 10; a.observe({ observedAt: at(10), processes: [row(100, 1, native)] });
    return a;
  }
  function pending() {
    const a = observer(); now = 20;
    a.observe({ observedAt: at(20), processes: [row(101, 100, native), row(100, 1, native)] });
    return a;
  }

  it("keeps the raw image and a nonpassing pending journal, then resolves only the exact helper", () => {
    const a = pending(), provisional = a.evidence();
    expect(provisional.state).toBe("unknown"); expect(provisional.errors).toContain("child_exec_transition_pending");
    expect(provisional.modelStartCount).toBe(1); expect(provisional.observedNativeImageStarts).toBe(2);
    expect(provisional.childExecTransitions?.[0]).toMatchObject({ pid: 101, start: "start-101", parent: 100,
      parentStart: "start-100", state: "pending", firstObservedAt: at(20), deadlineAt: at(270) });
    now = 70; a.observe({ observedAt: at(70), processes: [row(100, 1, native), row(101, 100, helper)] });
    const result = a.evidence(); expect(result.state).toBe("bounded_observed"); expect(result.errors).toEqual([]);
    expect(result.modelStartCount).toBe(1); expect(result.observedNativeImageStarts).toBe(2);
    expect(result.childExecTransitions?.[0]).toMatchObject({ state: "resolved_helper", resolvedAt: at(70) });
    expect(result.observations.filter((r) => r.pid === 101).map((r) => r.classification)).toEqual(["native_model", "declared_helper"]);
    expect(result.transitions.map((t) => t.kind)).toContain("exec_change");
  });
  it("does not change legacy counting without explicit opt-in", () => {
    delete options.rootChildExecTransition;
    const a = observer(); now = 20;
    a.observe({ observedAt: at(20), processes: [row(100, 1, native), row(101, 100, native)] });
    now = 70; a.observe({ observedAt: at(70), processes: [row(100, 1, native), row(101, 100, helper)] });
    expect(a.evidence().state).toBe("unknown"); expect(a.evidence().modelStartCount).toBe(2);
    expect(a.evidence().errors).toContain("native_start_budget_exceeded");
    expect(a.evidence()).not.toHaveProperty("childExecTransitions");
  });
  it("rejects a genuine second worker, including expiry without any new observation", () => {
    const a = pending(); now = 270;
    expect(a.evidence().errors).toContain("child_exec_transition_deadline_exceeded");
    expect(a.evidence().modelStartCount).toBe(2); expect(a.evidence().state).toBe("unknown");
    now = 271; a.observe({ observedAt: at(271), processes: [row(100, 1, native), row(101, 100, helper)] });
    expect(a.evidence().state).toBe("unknown"); expect(a.evidence().childExecTransitions?.[0].state).toBe("rejected");
    const independent = observer(); now = 20;
    independent.observe({ observedAt: at(20), processes: [row(100, 1, native), row(102, 1, native)] });
    expect(independent.evidence().errors).toContain("unexpected_model_start");
    expect(independent.evidence().modelStartCount).toBe(2);
  });
  it("requires both clocks strictly before the deadline", () => {
    for (const [wall, mono, pass] of [[269, 269, true], [270, 269, false], [269, 270, false]] as const) {
      const a = pending(); now = mono;
      a.observe({ observedAt: at(wall), processes: [row(100, 1, native), row(101, 100, helper)] });
      expect(a.evidence().state === "bounded_observed").toBe(pass);
    }
  });
  it("rejects missing, unknown, reused and reparented identities and never repairs them later", () => {
    for (const kind of ["missing", "unknown", "reuse", "reparent", "parent_missing", "incomplete"] as const) {
      const a = pending(); now = 30;
      const child = row(101, kind === "reparent" ? 1 : 100, kind === "unknown" ? null : helper,
        kind === "reuse" ? "replacement" : "start-101");
      const rows = kind === "missing" ? [row(100, 1, native)] : kind === "parent_missing" ? [child] : [row(100, 1, native), child];
      a.observe({ observedAt: at(30), processes: rows, complete: kind !== "incomplete" });
      expect(a.evidence().state, kind).toBe("unknown");
      now = 70; a.observe({ observedAt: at(70), processes: [row(100, 1, native), row(101, 100, helper)] });
      expect(a.evidence().state, kind).toBe("unknown");
      expect(a.evidence().childExecTransitions?.[0].state, kind).toBe("rejected");
    }
  });
  it("rejects same-frame root establishment, another child and helper-to-native regression", () => {
    const ambiguous = createProcessAccounting(options); ambiguous.bindRoot({ runId: "simulated", rootPid: 100 });
    now = 10; ambiguous.observe({ observedAt: at(10), processes: [row(100, 1, native), row(101, 100, native)] });
    expect(ambiguous.evidence().modelStartCount).toBe(2); expect(ambiguous.evidence().childExecTransitions).toEqual([]);
    const a = pending(); now = 40;
    a.observe({ observedAt: at(40), processes: [row(100, 1, native), row(101, 100, helper)] });
    now = 50; a.observe({ observedAt: at(50), processes: [row(100, 1, native), row(101, 100, native)] });
    expect(a.evidence().errors).toContain("child_exec_transition_helper_regressed"); expect(a.evidence().modelStartCount).toBe(2);
    const b = pending(); now = 40;
    b.observe({ observedAt: at(40), processes: [row(100, 1, native), row(101, 100, helper), row(102, 100, native)] });
    expect(b.evidence().errors).toContain("native_start_budget_exceeded"); expect(b.evidence().childExecTransitions).toHaveLength(1);
  });
  it("roundtrips only an explicit supported policy and rejects broad or invalid grants", () => {
    const { baseline: _baseline, ...policy } = options;
    expect(parseProcessAccountingPolicy(policy)?.rootChildExecTransition).toEqual(options.rootChildExecTransition);
    for (const change of [{ deadlineMs: 0 }, { deadlineMs: 1001 }, { helperPinId: "native" },
      { parentPinId: "helper" }, { sourceCommit: "unknown" }, { sourceEvidenceSha256: "missing" }, { maxChildren: 99 }]) {
      expect(() => createProcessAccounting({ ...options, rootChildExecTransition: { ...options.rootChildExecTransition!, ...change } })).toThrow("invalid_root_child_exec_transition");
    }
    expect(() => createProcessAccounting({ ...options, expectedNativeStarts: 2 })).toThrow("invalid_root_child_exec_transition");
    expect(() => parseProcessAccountingPolicy({ ...policy, exemptChildren: true })).toThrow();
  });
  it("never treats a previously seen unowned PID as fresh, and fails closed when history fills", () => {
    const a = observer(); now = 12;
    a.observe({ observedAt: at(12), processes: [row(100, 1, native), row(200, 1, helper)] });
    now = 15; a.observe({ observedAt: at(15), processes: [row(100, 1, native)] });
    now = 20; a.observe({ observedAt: at(20), processes: [row(100, 1, native), row(200, 100, native)] });
    expect(a.evidence().childExecTransitions).toEqual([]);
    expect(a.evidence().modelStartCount).toBe(2); expect(a.evidence().state).toBe("unknown");
    const b = observer({ ...options, bounds: { maxProcesses: 2 } }); now = 12;
    b.observe({ observedAt: at(12), processes: [row(100, 1, native), row(200, 1, helper)] });
    now = 15; b.observe({ observedAt: at(15), processes: [row(100, 1, native), row(201, 1, helper)] });
    expect(b.evidence().errors).toContain("child_exec_transition_history_limit");
    expect(b.evidence().state).toBe("unknown");
  });
});
