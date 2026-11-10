import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createProcessAccounting, type ProcessAccountingOptions } from "./process-accounting.js";
import type { ProcessIdentity } from "./process-containment.js";

// Synthetic artifact files identify simulated rows, never real model executions.
describe("prospective bounded process accounting", () => {
  let directory: string;
  let options: ProcessAccountingOptions;
  let node: string; let native: string; let python: string;
  const at = (ms: number) => new Date(Date.UTC(2026, 10, 10) + ms).toISOString();
  const row = (pid: number, parent: number, executable: string | null, start = `start-${pid}`): ProcessIdentity =>
    ({ pid, parent, executable, start, state: "S" });
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "paperclip-accounting-"));
    [node, native, python] = ["node", "native", "python"].map((name) => {
      const path = join(directory, name); writeFileSync(path, `synthetic-${name}`); return path;
    });
    options = { baseline: { observedAt: at(0), processes: [] }, sourceCommit: "a".repeat(40),
      contractSha256: "b".repeat(64), expectedNativeStarts: 1, rootLauncherPinId: "node",
      pins: [["node", node, "node_helper"], ["native", native, "native_model"], ["python", python, "python_helper"]]
        .map(([id, path, classification]) => ({ id, path, classification: classification as "node_helper" | "native_model" | "python_helper",
          sha256: createHash("sha256").update(readFileSync(path)).digest("hex") })) };
  });
  afterEach(() => { vi.restoreAllMocks(); rmSync(directory, { recursive: true, force: true }); });
  const bind = (accounting: ReturnType<typeof createProcessAccounting>) => accounting.bindRoot({ runId: "official-run", rootPid: 100 });

  it("binds baseline/source/contract and distinguishes root launcher, helpers, and one native start", () => {
    const accounting = createProcessAccounting(options); bind(accounting);
    const processes = [row(100, 1, node), row(101, 100, node), row(102, 100, python), row(103, 101, native)];
    accounting.observe({ observedAt: at(50), processes });
    accounting.observe({ observedAt: at(100), processes });
    const result = accounting.evidence();
    expect(result.state).toBe("bounded_observed"); expect(result.errors).toEqual([]);
    expect(result.modelStartCount).toBe(1); expect(result.observations).toHaveLength(4);
    expect(result.observations.map((r) => r.classification)).toEqual(["known_launcher", "node_helper", "python_helper", "native_model"]);
    expect(result.baselineDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(result.sourceCommit).toBe(options.sourceCommit); expect(result.contractSha256).toBe(options.contractSha256);
    expect(result.root).toEqual({ pid: 100, start: "start-100" });
    const changed = createProcessAccounting({ ...options, sourceCommit: "c".repeat(40) });
    expect(changed.evidence().baselineDigest).not.toBe(result.baselineDigest);
  });
  it("excludes an existing baseline model but gates a newly observed pinned model outside the root", () => {
    options.baseline.processes = [row(50, 1, native)]; options.expectedNativeStarts = 0;
    const accounting = createProcessAccounting(options); bind(accounting);
    accounting.observe({ observedAt: at(50), processes: [row(50, 1, native), row(100, 1, node)] });
    expect(accounting.evidence().state).toBe("bounded_observed");
    accounting.observe({ observedAt: at(100), processes: [row(50, 1, native), row(100, 1, node), row(200, 1, native)] });
    expect(accounting.evidence().modelStartCount).toBe(1);
    expect(accounting.evidence().errors).toContain("unexpected_model_start");
    expect(accounting.evidence().state).toBe("unknown");
  });
  it("retains a vanished native identity and reparenting rather than inferring its lifetime from a terminal snapshot", () => {
    const accounting = createProcessAccounting(options); bind(accounting);
    accounting.observe({ observedAt: at(50), processes: [row(100, 1, node), row(101, 100, native)] });
    accounting.observe({ observedAt: at(100), processes: [row(101, 1, native)] });
    accounting.observe({ observedAt: at(150), processes: [] });
    const result = accounting.evidence();
    expect(result.modelStartCount).toBe(1); expect(result.observations.find((r) => r.pid === 101)?.owned).toBe(true);
    expect(result.transitions.map((t) => t.kind)).toContain("reparent"); expect(result.state).toBe("bounded_observed");
  });
  it("counts PID reuse and helper-to-native executable transitions as new native starts", () => {
    const accounting = createProcessAccounting(options); bind(accounting);
    accounting.observe({ observedAt: at(50), processes: [row(100, 1, node), row(101, 100, native, "old")] });
    accounting.observe({ observedAt: at(100), processes: [row(100, 1, node), row(101, 100, node, "new")] });
    accounting.observe({ observedAt: at(150), processes: [row(100, 1, node), row(101, 100, native, "new")] });
    const result = accounting.evidence();
    expect(result.modelStartCount).toBe(2); expect(result.errors).toContain("native_start_budget_exceeded");
    expect(result.transitions.map((t) => t.kind)).toEqual(["pid_reuse", "exec_change"]);
    expect(result.observations.filter((r) => r.pid === 101)).toHaveLength(3);
  });
  it("preserves PID reuse history even after an empty intermediate snapshot", () => {
    const accounting = createProcessAccounting(options); bind(accounting);
    accounting.observe({ observedAt: at(50), processes: [row(100, 1, node), row(101, 100, native, "old")] });
    accounting.observe({ observedAt: at(100), processes: [row(100, 1, node)] });
    accounting.observe({ observedAt: at(150), processes: [row(100, 1, node), row(101, 100, native, "new")] });
    expect(accounting.evidence().transitions.map((t) => t.kind)).toContain("pid_reuse");
    expect(accounting.evidence().modelStartCount).toBe(2);
  });
  it("classifies unknown owned paths without opening or exporting their contents/extra fields", () => {
    const secretPath = join(directory, "not-a-pin"); writeFileSync(secretPath, "PRIVATE-CONTENT-CANARY");
    options.expectedNativeStarts = 0;
    const accounting = createProcessAccounting(options); bind(accounting);
    const unknown = { ...row(101, 100, secretPath), args: "ARGUMENT-CANARY", env: "ENV-CANARY" };
    accounting.observe({ observedAt: at(50), processes: [row(100, 1, node), unknown] });
    const result = accounting.evidence();
    expect(result.errors).toContain("unknown_owned_executable");
    expect(JSON.stringify(result)).not.toMatch(/PRIVATE-CONTENT-CANARY|ARGUMENT-CANARY|ENV-CANARY/);
  });
  it("fails closed for missing binding, unavailable root, partial samples, gaps and reversed times", () => {
    const accounting = createProcessAccounting(options);
    accounting.observe({ observedAt: at(3000), processes: [], complete: false }); bind(accounting);
    accounting.observe({ observedAt: at(2000), processes: [] });
    expect(accounting.evidence().state).toBe("unknown");
    expect(accounting.evidence().errors).toEqual(expect.arrayContaining(["snapshot_gap", "snapshot_incomplete",
      "snapshot_time_reversed", "root_not_bound", "root_bound_after_observation", "root_identity_unavailable", "model_start_count_mismatch"]));
  });
  it("does not accept malformed, duplicate PID or oversized snapshots and enforces finite counters", () => {
    options.bounds = { maxProcesses: 1, maxSamples: 2 };
    const accounting = createProcessAccounting(options); bind(accounting);
    accounting.observe({ observedAt: at(50), processes: [row(100, 1, node), row(101, 100, native)] });
    accounting.observe({ observedAt: at(100), processes: [{ ...row(100, 1, node), start: "unsafe\ntext" }] });
    accounting.observe({ observedAt: at(150), processes: [] });
    expect(accounting.evidence().errors).toEqual(expect.arrayContaining(["invalid_or_oversize_snapshot", "sample_limit"]));
    const duplicate = createProcessAccounting(options); bind(duplicate);
    duplicate.observe({ observedAt: at(50), processes: [row(100, 1, node), row(100, 1, native)] });
    expect(duplicate.evidence().state).toBe("unknown");
  });
  it("gates exhausted observation and transition bounds without silently claiming completeness", () => {
    options.bounds = { maxObservations: 2, maxTransitions: 1 };
    const accounting = createProcessAccounting(options); bind(accounting);
    accounting.observe({ observedAt: at(50), processes: [row(100, 1, node), row(101, 100, native)] });
    accounting.observe({ observedAt: at(100), processes: [row(100, 1, node), row(101, 100, python)] });
    accounting.observe({ observedAt: at(150), processes: [row(100, 1, node), row(101, 100, native)] });
    expect(accounting.evidence().state).toBe("unknown");
    expect(accounting.evidence().observations.length).toBeLessThanOrEqual(2);
    expect(accounting.evidence().transitions.length).toBeLessThanOrEqual(1);
    expect(accounting.evidence().errors).toEqual(expect.arrayContaining(["observation_limit", "transition_limit"]));
  });
  it("checks only declared artifact hashes and gates a changed declared pin", () => {
    expect(() => createProcessAccounting({ ...options, pins: [{ ...options.pins[0], sha256: "0".repeat(64) }] })).toThrow("pin_unavailable_or_mismatch");
    const accounting = createProcessAccounting(options); bind(accounting);
    writeFileSync(native, "replacement");
    accounting.observe({ observedAt: at(50), processes: [row(100, 1, node), row(101, 100, native)] });
    expect(accounting.evidence().errors).toContain("executable_pin_changed");
  });
  it("returns detached evidence and policy snapshots so callers cannot clear the actual gate", () => {
    const accounting = createProcessAccounting(options); bind(accounting);
    options.expectedNativeStarts = 0; options.sourceCommit = "c".repeat(40);
    accounting.observe({ observedAt: at(50), processes: [row(100, 1, node)] });
    const report = accounting.evidence(); report.errors.length = 0; report.state = "bounded_observed";
    expect(accounting.evidence().state).toBe("unknown"); expect(accounting.evidence().sourceCommit).toBe("a".repeat(40));
  });
});
