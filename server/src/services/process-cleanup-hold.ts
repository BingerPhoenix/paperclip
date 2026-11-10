import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { conflict } from "../errors.js";

/** Existing agent metadata persists a review gate across service restarts. */
export function hasProcessCleanupHold(agent: { metadata?: unknown } | null | undefined): boolean {
  const metadata = agent?.metadata;
  return !!metadata && typeof metadata === "object" && "processCleanupHold" in metadata;
}

export function processCleanupHoldMetadata(metadata: unknown, runId: string, reason: string, accountingRequired = false) {
  return {
    ...(metadata && typeof metadata === "object" && !Array.isArray(metadata) ? metadata : {}),
    processCleanupHold: {
      holdId: randomUUID(), runId, reason, state: "review_required",
      scope: "sampled_pid_start_identity", createdAt: new Date().toISOString(), accountingRequired,
    },
  };
}

const uuid = z.string().uuid();
const digest = z.string().regex(/^[a-f0-9]{64}$/);
export const releaseProcessCleanupHoldRequestSchema = z.object({
  expectedHoldId: uuid,
  expectedRunId: uuid,
  reviewedCleanupEvidenceSha256: digest,
  reviewNote: z.string().trim().min(1).max(2000),
}).strict().refine((value) => value.expectedHoldId !== value.expectedRunId, {
  message: "Hold identity must be distinct from run identity", path: ["expectedHoldId"],
});
export type ReleaseProcessCleanupHoldRequest = z.infer<typeof releaseProcessCleanupHoldRequestSchema>;

const holdSchema = z.object({
  holdId: uuid, runId: uuid, state: z.literal("review_required"),
  scope: z.literal("sampled_pid_start_identity"),
}).passthrough();
export function readProcessCleanupHold(metadata: unknown) {
  const raw = metadata && typeof metadata === "object" && !Array.isArray(metadata)
    ? (metadata as Record<string, unknown>).processCleanupHold : undefined;
  const parsed = holdSchema.safeParse(raw);
  if (!parsed.success || parsed.data.holdId === parsed.data.runId) throw conflict("A current identified process cleanup hold is required");
  return parsed.data;
}

// Canonicalize the complete official evidence, including its accounting/history.
// Limits prevent malformed stored JSON from consuming unbounded stack or memory.
export function processCleanupEvidenceSha256(evidence: unknown): string {
  let entries = 0;
  const canonical = (value: unknown, depth = 0): string => {
    if (depth > 32 || ++entries > 100_000) throw conflict("Malformed process cleanup evidence");
    if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
    if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map((v) => canonical(v, depth + 1)).join(",")}]`;
    if (value && typeof value === "object") return `{${Object.keys(value).sort().map((k) =>
      `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k], depth + 1)}`).join(",")}}`;
    throw conflict("Malformed process cleanup evidence");
  };
  const text = canonical(evidence);
  if (Buffer.byteLength(text) > 1024 * 1024) throw conflict("Process cleanup evidence exceeds the review limit");
  return createHash("sha256").update(text).digest("hex");
}

const identitySchema = z.object({
  pid: z.number().int().positive(), start: z.string().trim().min(1).max(256),
  parent: z.number().int().nonnegative(), executable: z.string().trim().min(1).max(4096),
  classification: z.enum(["native_model", "known_launcher", "node_helper", "python_helper", "declared_helper"]),
}).passthrough();
const evidenceSchema = z.object({
  scope: z.literal("sampled_pid_start_identity"), state: z.literal("observed_gone"),
  observed: z.number().int().positive(), remaining: z.literal(0), errors: z.array(z.string()).length(0),
  capturedIdentities: z.array(identitySchema).min(1).max(4096),
  accounting: z.object({
    scope: z.literal("bounded_sampled_process_accounting"), state: z.literal("bounded_observed"),
    runId: uuid, root: z.object({ pid: z.number().int().positive(), start: z.string().trim().min(1).max(256) }).passthrough(),
    baselineDigest: digest, baselineObservedAt: z.string().datetime({ offset: true }),
    sourceCommit: z.string().regex(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/), contractSha256: digest,
    expectedNativeStarts: z.number().int().min(0).max(1),
    modelStartCount: z.number().int().min(0).max(1), errors: z.array(z.string()).length(0),
  }).passthrough(),
}).passthrough();

export function validateReviewedProcessCleanup(input: {
  cleanup: unknown;
  expectedRunId: string;
  reviewedCleanupEvidenceSha256: string;
  processPid: number | null;
  adapterType: string;
  snapshot: readonly { pid: number; start: string; state: string }[];
}): void {
  if (processCleanupEvidenceSha256(input.cleanup) !== input.reviewedCleanupEvidenceSha256) {
    throw conflict("Reviewed cleanup evidence does not match the official run");
  }
  const parsed = evidenceSchema.safeParse(input.cleanup);
  if (!parsed.success) throw conflict("Official process cleanup evidence is unresolved or malformed");
  const evidence = parsed.data;
  const accounting = evidence.accounting;
  if (accounting.runId !== input.expectedRunId || accounting.root.pid !== input.processPid
      || !evidence.capturedIdentities.some((id) => id.pid === accounting.root.pid && id.start === accounting.root.start)
      || evidence.observed !== evidence.capturedIdentities.length) {
    throw conflict("Process cleanup evidence is not bound to this official run");
  }
  const modelCount = input.adapterType === "process" ? 0 : input.adapterType === "codex_local" ? 1 : null;
  if (modelCount === null || accounting.expectedNativeStarts !== modelCount || accounting.modelStartCount !== modelCount) {
    throw conflict("Process model-worker accounting is not qualified for release");
  }
  const keys = evidence.capturedIdentities.map((id) => `${id.pid}:${id.start}`);
  if (new Set(keys).size !== keys.length) throw conflict("Captured process identities are ambiguous");
  if (evidence.capturedIdentities.some((id) => input.snapshot.some((current) =>
    current.pid === id.pid && current.start === id.start && !current.state.startsWith("Z")))) {
    throw conflict("A captured process identity is still live");
  }
}
