/** Single-server fences; durable agent metadata remains the restart boundary. */
export const processAdmissionHolds = new Set<string>();
export const agentProcessAdmissionHolds = new Set<string>();
const holdIdentities = new Map<string, { runId: string; holdId: string | null }>();

export function markProcessAdmissionHold(agentId: string, runId: string, holdId: string | null = null) {
  processAdmissionHolds.add(runId);
  agentProcessAdmissionHolds.add(agentId);
  holdIdentities.set(agentId, { runId, holdId });
}

/** A stale release must never remove a newer/pending cancellation fence. */
export function clearProcessAdmissionHold(agentId: string, expected: { holdId: string; runId: string }): boolean {
  const current = holdIdentities.get(agentId);
  if (current && (current.runId !== expected.runId || current.holdId !== expected.holdId)) return false;
  if (!current && agentProcessAdmissionHolds.has(agentId)) return false;
  holdIdentities.delete(agentId);
  agentProcessAdmissionHolds.delete(agentId);
  processAdmissionHolds.delete(expected.runId);
  return true;
}
