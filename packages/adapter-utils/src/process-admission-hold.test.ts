import { describe, expect, it } from "vitest";
import { agentProcessAdmissionHolds, processAdmissionHolds, markProcessAdmissionHold, clearProcessAdmissionHold } from "./process-admission-hold.js";

describe("reviewed single-server fence release", () => {
  it("clears only the matching persisted hold identity", () => {
    markProcessAdmissionHold("fixture-match", "run-a", "hold-a");
    expect(clearProcessAdmissionHold("fixture-match", { runId: "run-a", holdId: "hold-a" })).toBe(true);
    expect(agentProcessAdmissionHolds.has("fixture-match")).toBe(false);
    expect(processAdmissionHolds.has("run-a")).toBe(false);
  });
  it("preserves concurrently replaced and pending holds", () => {
    markProcessAdmissionHold("fixture-replaced", "run-b", "hold-b");
    markProcessAdmissionHold("fixture-replaced", "run-b", "hold-new");
    expect(clearProcessAdmissionHold("fixture-replaced", { runId: "run-b", holdId: "hold-b" })).toBe(false);
    expect(agentProcessAdmissionHolds.has("fixture-replaced")).toBe(true);
    markProcessAdmissionHold("fixture-replaced", "run-c");
    expect(clearProcessAdmissionHold("fixture-replaced", { runId: "run-b", holdId: "hold-new" })).toBe(false);
    markProcessAdmissionHold("fixture-replaced", "run-c", "hold-c");
    expect(clearProcessAdmissionHold("fixture-replaced", { runId: "run-c", holdId: "hold-c" })).toBe(true);
    processAdmissionHolds.delete("run-b");
  });
  it("permits a durable verified release after restart without inventing a local fence", () => {
    expect(clearProcessAdmissionHold("fixture-restarted", { runId: "run-d", holdId: "hold-d" })).toBe(true);
    agentProcessAdmissionHolds.add("fixture-unversioned");
    expect(clearProcessAdmissionHold("fixture-unversioned", { runId: "run-e", holdId: "hold-e" })).toBe(false);
    agentProcessAdmissionHolds.delete("fixture-unversioned");
  });
});
