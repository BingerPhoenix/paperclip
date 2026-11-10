/** Existing agent metadata persists a review gate across service restarts. */
export function hasProcessCleanupHold(agent: { metadata?: unknown } | null | undefined): boolean {
  const metadata = agent?.metadata;
  return !!metadata && typeof metadata === "object" && "processCleanupHold" in metadata;
}
export function processCleanupHoldMetadata(metadata: unknown, runId: string, reason: string) {
  return { ...(metadata && typeof metadata === "object" && !Array.isArray(metadata) ? metadata : {}),
    processCleanupHold: { runId, reason, state: "review_required", scope: "sampled_pid_start_identity" } };
}
