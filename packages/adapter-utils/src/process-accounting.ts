import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import type { ProcessIdentity } from "./process-containment.js";

export type ExecutableClassification = "native_model" | "known_launcher" | "node_helper" |
  "python_helper" | "declared_helper" | "unknown";
export interface ExecutablePin {
  id: string;
  path: string;
  sha256: string;
  classification: Exclude<ExecutableClassification, "unknown" | "known_launcher">;
}
export interface ProcessAccountingOptions {
  baseline: { observedAt: string; processes: ProcessIdentity[] };
  sourceCommit: string;
  contractSha256: string;
  pins: ExecutablePin[];
  expectedNativeStarts: number;
  rootLauncherPinId?: string;
  rootChildExecTransition?: RootChildExecTransitionPolicy;
  bounds?: { maxGapMs?: number; maxSamples?: number; maxProcesses?: number;
    maxObservations?: number; maxTransitions?: number };
}
export interface RootChildExecTransitionPolicy {
  parentPinId: string; helperPinId: string; deadlineMs: number;
  sourceCommit: string; sourceEvidenceSha256: string;
}
export interface ChildExecTransitionEvidence {
  runId: string; pid: number; start: string; parent: number; parentStart: string;
  fromPinId: string; helperPinId: string; firstObservedAt: string; deadlineAt: string;
  state: "pending" | "resolved_helper" | "rejected"; resolvedAt?: string; reason?: string;
}
export interface ClassifiedProcessIdentity {
  pid: number; start: string; parent: number; executable: string | null;
  classification: ExecutableClassification;
}
export interface ProcessObservation extends ClassifiedProcessIdentity {
  state: string;
  firstObservedAt: string; lastObservedAt: string; pinId: string | null;
  artifactSha256: string | null; owned: boolean; runId: string | null;
}
export interface ProcessTransition {
  kind: "pid_reuse" | "exec_change" | "reparent";
  observedAt: string; pid: number; start: string;
  previousStart: string; fromExecutable: string | null; toExecutable: string | null;
}
export interface ProcessAccountingEvidence {
  scope: "bounded_sampled_process_accounting";
  state: "bounded_observed" | "unknown";
  runId: string | null;
  root: { pid: number; start: string } | null;
  expectedNativeStarts: number; modelStartCount: number;
  errors: string[];
  baselineDigest: string; baselineObservedAt: string;
  sourceCommit: string; contractSha256: string;
  baselineProcesses: ClassifiedProcessIdentity[];
  pins: ExecutablePin[];
  sampleCount: number; maxObservedGapMs: number;
  bounds: Required<NonNullable<ProcessAccountingOptions["bounds"]>>;
  observations: ProcessObservation[];
  transitions: ProcessTransition[];
  rootChildExecTransition?: RootChildExecTransitionPolicy;
  observedNativeImageStarts?: number;
  childExecTransitions?: ChildExecTransitionEvidence[];
  limitations: string[];
}
export interface ProcessAccountingObserver {
  rejectAdmission(): void;
  bindRoot(binding: { runId: string; rootPid: number }): void;
  observe(snapshot: { observedAt: string; processes: ProcessIdentity[]; complete?: boolean }): void;
  evidence(): ProcessAccountingEvidence;
}

const hash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const key = (row: ProcessIdentity) => `${row.pid}:${row.start}`;
const safeText = (value: unknown, max: number): value is string => typeof value === "string" &&
  value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(value);
const timestamp = (value: unknown) => typeof value === "string" &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value) && Number.isFinite(Date.parse(value));
const validRow = (row: ProcessIdentity) => row && Number.isSafeInteger(row.pid) && row.pid > 0 &&
  Number.isSafeInteger(row.parent) && row.parent >= 0 && safeText(row.start, 128) && safeText(row.state, 32) &&
  (row.executable == null || (safeText(row.executable, 4096) && isAbsolute(row.executable)));

/** Samples a declared scope; it cannot prove absence between samples or hostile containment. */
export function createProcessAccounting(options: ProcessAccountingOptions): ProcessAccountingObserver {
  // Do not let a caller mutate policy/baseline after admission.
  options = structuredClone(options);
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(options.sourceCommit) ||
      !/^[a-f0-9]{64}$/.test(options.contractSha256) ||
      !Number.isSafeInteger(options.expectedNativeStarts) || options.expectedNativeStarts < 0 ||
      options.expectedNativeStarts > 2 || !Array.isArray(options.pins) || options.pins.length > 64 ||
      !options.baseline || !timestamp(options.baseline.observedAt)) throw new Error("invalid_process_accounting_policy");
  const bounds = { maxGapMs: 2000, maxSamples: 4000, maxProcesses: 8192,
    maxObservations: 512, maxTransitions: 512, ...options.bounds };
  for (const [name, value] of Object.entries(bounds)) {
    const cap = name === "maxGapMs" ? 60_000 : name === "maxSamples" ? 100_000 : 16_384;
    if (!Number.isSafeInteger(value) || value < 1 || value > cap) throw new Error("invalid_process_accounting_bounds");
  }
  const errors = new Set<string>();
  const pins: (ExecutablePin & { originalPath: string; fingerprint: string })[] = [];
  const fingerprint = (path: string) => {
    const stat = statSync(path);
    if (!stat.isFile()) throw new Error("not_regular_file");
    return `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}:${stat.ctimeMs}`;
  };
  const classifications = new Set(["native_model", "node_helper", "python_helper", "declared_helper"]);
  for (const pin of options.pins) {
    if (!pin || !/^[a-zA-Z0-9_.-]{1,64}$/.test(pin.id) || !safeText(pin.path, 4096) ||
        !isAbsolute(pin.path) || !/^[a-f0-9]{64}$/.test(pin.sha256) || !classifications.has(pin.classification) ||
        pins.some((p) => p.id === pin.id)) throw new Error("invalid_executable_pin");
    // Only operator-declared artifacts are opened. Never open a path from a process snapshot.
    try {
      const canonical = realpathSync(pin.path);
      const before = fingerprint(canonical);
      if (hash(readFileSync(canonical)) !== pin.sha256 || fingerprint(canonical) !== before ||
          pins.some((p) => p.path === canonical)) throw new Error("pin_mismatch");
      pins.push({ id: pin.id, sha256: pin.sha256, classification: pin.classification,
        path: canonical, originalPath: resolve(pin.path), fingerprint: before });
    } catch { throw new Error("executable_pin_unavailable_or_mismatch"); }
  }
  if (options.rootLauncherPinId && !pins.some((p) => p.id === options.rootLauncherPinId && p.classification !== "native_model")) {
    throw new Error("invalid_root_launcher_pin");
  }
  const childRule = options.rootChildExecTransition;
  if (childRule !== undefined && (!childRule || typeof childRule !== "object" || Array.isArray(childRule) ||
      Object.keys(childRule).some((k) => !["parentPinId", "helperPinId", "deadlineMs", "sourceCommit", "sourceEvidenceSha256"].includes(k)) ||
      options.expectedNativeStarts !== 1 || !Number.isSafeInteger(childRule.deadlineMs) || childRule.deadlineMs < 1 || childRule.deadlineMs > 1000 ||
      !/^[a-f0-9]{40}$/.test(childRule.sourceCommit) || !/^[a-f0-9]{64}$/.test(childRule.sourceEvidenceSha256) ||
      !pins.some((p) => p.id === childRule.parentPinId && p.classification === "native_model") ||
      !pins.some((p) => p.id === childRule.helperPinId && p.classification === "declared_helper"))) {
    throw new Error("invalid_root_child_exec_transition");
  }
  let runId: string | null = null;
  let rootPid: number | null = null;
  let root: { pid: number; start: string } | null = null;
  let sampleCount = 0;
  let modelStartCount = 0;
  let observedNativeImageStarts = 0;
  let previousSnapshotComplete = false;
  let previousMonotonic: number | null = null;
  const childExecTransitions: ChildExecTransitionEvidence[] = [];
  let childCandidate: { record: ChildExecTransitionEvidence; firstMonotonic: number; parentParent: number } | null = null;
  let previousAt = Date.parse(options.baseline.observedAt);
  let maxObservedGapMs = 0;
  const owned = new Set<string>();
  const latest = new Map<string, ProcessIdentity>();
  const latestPid = new Map<number, ProcessIdentity>();
  const observations: ProcessObservation[] = [];
  const lastObservation = new Map<string, ProcessObservation>();
  const transitions: ProcessTransition[] = [];
  const classify = (row: ProcessIdentity): ClassifiedProcessIdentity & { pinId: string | null; artifactSha256: string | null } => {
    const executable = row.executable ?? null;
    const pin = pins.find((p) => executable === p.path || executable === p.originalPath);
    const launcher = pin && root?.pid === row.pid && root.start === row.start && pin.id === options.rootLauncherPinId;
    return { pid: row.pid, start: row.start, parent: row.parent, executable,
      classification: launcher ? "known_launcher" : pin?.classification ?? "unknown",
      pinId: pin?.id ?? null, artifactSha256: pin?.sha256 ?? null };
  };
  const validSnapshot = (rows: ProcessIdentity[]) => Array.isArray(rows) && rows.length <= bounds.maxProcesses &&
    rows.every(validRow) && new Set(rows.map((row) => row.pid)).size === rows.length;
  const baseline = options.baseline.processes;
  if (!validSnapshot(baseline)) throw new Error("invalid_process_accounting_baseline");
  // Freshness cannot rely on latest/scoped rows: an earlier unowned PID may
  // disappear and later reparent. Opt-in history is bounded and never evicted.
  const seenHostPids = childRule ? new Set(baseline.map((row) => row.pid)) : null;
  const baselineProcesses = baseline.map((row) => {
    latest.set(key(row), { ...row }); latestPid.set(row.pid, { ...row });
    const { pinId: _pinId, artifactSha256: _sha, ...safe } = classify(row);
    return safe;
  }).sort((a, b) => a.pid - b.pid || a.start.localeCompare(b.start));
  const baselineDigest = hash(JSON.stringify({ observedAt: options.baseline.observedAt,
    sourceCommit: options.sourceCommit, contractSha256: options.contractSha256, processes: baselineProcesses }));
  const transition = (kind: ProcessTransition["kind"], row: ProcessIdentity, old: ProcessIdentity, at: string) => {
    if (transitions.length >= bounds.maxTransitions) { errors.add("transition_limit"); return; }
    transitions.push({ kind, observedAt: at, pid: row.pid, start: row.start, previousStart: old.start,
      fromExecutable: old.executable ?? null, toExecutable: row.executable ?? null });
  };
  const countNative = (isOwned: boolean) => {
    modelStartCount++;
    if (!isOwned) errors.add("unexpected_model_start");
    if (modelStartCount > options.expectedNativeStarts) errors.add("native_start_budget_exceeded");
  };
  const rejectChild = (reason: string) => {
    if (childCandidate?.record.state !== "pending") return;
    childCandidate.record.state = "rejected"; childCandidate.record.reason = reason;
    errors.add(`child_exec_transition_${reason}`);
    // The unresolved image was deferred, never deducted from a committed count.
    countNative(true);
  };
  const expireChild = (now: number, at?: number) => {
    if (!childRule) return;
    if (!Number.isFinite(now) || (previousMonotonic !== null && now < previousMonotonic)) {
      errors.add("monotonic_clock_invalid"); rejectChild("clock_invalid");
    } else previousMonotonic = now;
    if (childCandidate?.record.state === "pending" &&
        (now - childCandidate.firstMonotonic >= childRule.deadlineMs ||
         (at !== undefined && at >= Date.parse(childCandidate.record.deadlineAt)))) rejectChild("deadline_exceeded");
  };
  return {
    rejectAdmission() { errors.add("additional_process_admission_rejected"); },
    bindRoot(binding) {
      if (!binding || !safeText(binding.runId, 128) || !Number.isSafeInteger(binding.rootPid) || binding.rootPid <= 0) {
        errors.add("invalid_root_binding"); return;
      }
      if (runId !== null) {
        if (runId !== binding.runId || rootPid !== binding.rootPid) errors.add("root_binding_changed");
        return;
      }
      runId = binding.runId; rootPid = binding.rootPid;
      if (baseline.some((row) => row.pid === rootPid)) errors.add("root_present_in_baseline");
      if (sampleCount) errors.add("root_bound_after_observation");
    },
    observe(snapshot) {
      const monotonicNow = performance.now();
      const priorComplete = previousSnapshotComplete; previousSnapshotComplete = false;
      expireChild(monotonicNow);
      sampleCount++;
      if (sampleCount > bounds.maxSamples) { errors.add("sample_limit"); rejectChild("missing_observation"); return; }
      if (!snapshot || !timestamp(snapshot.observedAt)) { errors.add("invalid_snapshot_time"); rejectChild("missing_observation"); return; }
      const at = Date.parse(snapshot.observedAt);
      const gap = at - previousAt;
      if (gap < 0) errors.add("snapshot_time_reversed");
      if (gap > bounds.maxGapMs) errors.add("snapshot_gap");
      maxObservedGapMs = Math.max(maxObservedGapMs, gap); previousAt = Math.max(previousAt, at);
      if (snapshot.complete === false) errors.add("snapshot_incomplete");
      expireChild(monotonicNow, at);
      if (!validSnapshot(snapshot.processes)) { errors.add("invalid_or_oversize_snapshot"); rejectChild("missing_observation"); return; }
      if (seenHostPids && seenHostPids.size + snapshot.processes.filter((row) => !seenHostPids.has(row.pid)).length > bounds.maxProcesses) {
        errors.add("child_exec_transition_history_limit"); rejectChild("history_limit");
      }
      for (const pin of pins) {
        try { if (fingerprint(pin.path) !== pin.fingerprint || realpathSync(pin.originalPath) !== pin.path) errors.add("executable_pin_changed"); }
        catch { errors.add("executable_pin_unavailable"); }
      }
      const rows = snapshot.processes.map((row) => {
        const previous = latest.get(key(row)) ?? lastObservation.get(key(row));
        // A known identity's terminal ps row can lose comm. Preserve its last
        // observed executable as history, never as a new live classification.
        return row.state.startsWith("Z") && row.executable == null && previous?.executable
          ? { ...row, executable: previous.executable } : row;
      });
      const byPid = new Map(rows.map((row) => [row.pid, row]));
      const priorRoot = root ? latest.get(`${root.pid}:${root.start}`) : undefined;
      if (!root && rootPid !== null) {
        const row = byPid.get(rootPid);
        if (row) { root = { pid: row.pid, start: row.start }; owned.add(key(row)); }
        else errors.add("root_identity_unavailable");
      }
      if (!runId || rootPid === null) errors.add("root_not_bound");
      let changed = true;
      while (changed) {
        changed = false;
        for (const row of rows) {
          const parent = byPid.get(row.parent);
          if (parent && owned.has(key(parent)) && !owned.has(key(row))) {
            if (owned.size >= bounds.maxObservations) { errors.add("owned_identity_limit"); continue; }
            owned.add(key(row)); changed = true;
          }
        }
      }
      if (childCandidate?.record.state === "pending") {
        const record = childCandidate.record;
        const child = byPid.get(record.pid), parent = byPid.get(record.parent);
        if (errors.size) rejectChild("invalid_observation");
        else if (!child) rejectChild("missing_observation");
        else if (child.start !== record.start) rejectChild("identity_reused");
        else if (!parent || parent.start !== record.parentStart || parent.parent !== childCandidate.parentParent ||
            parent.state.startsWith("Z") || classify(parent).pinId !== childRule!.parentPinId) rejectChild("parent_changed");
        else if (child.parent !== record.parent) rejectChild("reparented");
        else if (child.state.startsWith("Z")) rejectChild("terminal_before_helper");
        else {
          const image = classify(child);
          if (image.pinId === childRule!.helperPinId && image.classification === "declared_helper") {
            record.state = "resolved_helper"; record.resolvedAt = snapshot.observedAt;
          } else if (image.pinId !== record.fromPinId || image.classification !== "native_model") rejectChild("wrong_executable");
        }
      }
      if (childCandidate?.record.state === "resolved_helper") {
        const child = byPid.get(childCandidate.record.pid);
        if (child && (child.start !== childCandidate.record.start || classify(child).pinId !== childRule!.helperPinId)) {
          // A proven startup target does not authorize later images or PID reuse.
          errors.add("child_exec_transition_helper_changed");
        }
      }
      for (const row of rows) {
        const rowKey = key(row);
        const current = classify(row);
        const retainedSame = lastObservation.get(rowKey);
        const old = latest.get(rowKey) ?? (row.state.startsWith("Z") && retainedSame
          ? { ...retainedSame, state: "previously_observed" } : undefined);
        const retainedPrevious = observations.findLast((item) => item.pid === row.pid);
        const oldPid = latestPid.get(row.pid) ?? (retainedPrevious ? {
          ...retainedPrevious, state: "previously_observed" } : undefined);
        const isOwned = owned.has(rowKey);
        const native = current.classification === "native_model";
        const scoped = isOwned || native || lastObservation.has(rowKey);
        if (scoped) {
          if (oldPid && oldPid.start !== row.start) transition("pid_reuse", row, oldPid, snapshot.observedAt);
          if (old && (old.executable ?? null) !== (row.executable ?? null)) transition("exec_change", row, old, snapshot.observedAt);
          if (old && old.parent !== row.parent) transition("reparent", row, old, snapshot.observedAt);
          if (isOwned && current.classification === "unknown") errors.add("unknown_owned_executable");
          const oldClass = old ? classify(old) : null;
          if (native && (!old || oldClass?.classification !== "native_model" || oldClass.pinId !== current.pinId)) {
            observedNativeImageStarts++;
            const parent = root ? byPid.get(root.pid) : undefined;
            if (childRule && !childExecTransitions.length && !errors.size && priorComplete && modelStartCount === 1 &&
                isOwned && root && row.pid !== root.pid && row.parent === root.pid && !old && !oldPid &&
                !seenHostPids!.has(row.pid) && !observations.some((r) => r.pid === row.pid) &&
                !row.state.startsWith("Z") && priorRoot && parent && parent.start === root.start &&
                priorRoot.start === parent.start && priorRoot.parent === parent.parent && !parent.state.startsWith("Z") &&
                classify(priorRoot).pinId === childRule.parentPinId && classify(parent).pinId === childRule.parentPinId &&
                current.pinId === childRule.parentPinId) {
              const record: ChildExecTransitionEvidence = { runId: runId!, pid: row.pid, start: row.start,
                parent: parent.pid, parentStart: parent.start, fromPinId: current.pinId!, helperPinId: childRule.helperPinId,
                firstObservedAt: snapshot.observedAt, deadlineAt: new Date(at + childRule.deadlineMs).toISOString(), state: "pending" };
              childExecTransitions.push(record);
              childCandidate = { record, firstMonotonic: monotonicNow, parentParent: parent.parent };
            } else {
              countNative(isOwned);
              if (childCandidate?.record.state === "resolved_helper" && rowKey === `${childCandidate.record.pid}:${childCandidate.record.start}`) {
                errors.add("child_exec_transition_helper_regressed");
              }
            }
          }
          const previous = lastObservation.get(rowKey);
          if (previous && previous.executable === current.executable && previous.classification === current.classification) {
            previous.lastObservedAt = snapshot.observedAt;
            previous.state = row.state;
            previous.parent = row.parent;
            previous.owned ||= isOwned;
          } else if (observations.length < bounds.maxObservations) {
            const observation = { ...current, state: row.state, firstObservedAt: snapshot.observedAt, lastObservedAt: snapshot.observedAt,
              owned: isOwned, runId };
            observations.push(observation); lastObservation.set(rowKey, observation);
          } else errors.add("observation_limit");
        }
        // Latest full host snapshot is bounded separately; exited identities remain only in observations.
      }
      latest.clear(); latestPid.clear();
      for (const row of rows) { latest.set(key(row), { ...row }); latestPid.set(row.pid, { ...row }); }
      previousSnapshotComplete = snapshot.complete !== false;
      if (seenHostPids) for (const row of rows) {
        if (seenHostPids.has(row.pid) || seenHostPids.size < bounds.maxProcesses) seenHostPids.add(row.pid);
      }
    },
    evidence() {
      expireChild(performance.now());
      const allErrors = new Set(errors);
      if (!runId || !root) allErrors.add("root_identity_unavailable");
      if (!sampleCount) allErrors.add("no_post_admission_snapshot");
      if (modelStartCount !== options.expectedNativeStarts) allErrors.add("model_start_count_mismatch");
      if (childCandidate?.record.state === "pending") allErrors.add("child_exec_transition_pending");
      return structuredClone({ scope: "bounded_sampled_process_accounting" as const,
        state: allErrors.size ? "unknown" as const : "bounded_observed" as const,
        runId, root, expectedNativeStarts: options.expectedNativeStarts, modelStartCount,
        errors: [...allErrors].sort(), baselineDigest, baselineObservedAt: options.baseline.observedAt,
        sourceCommit: options.sourceCommit, contractSha256: options.contractSha256,
        baselineProcesses, pins: pins.map(({ originalPath: _original, fingerprint: _fingerprint, ...pin }) => pin),
        sampleCount, maxObservedGapMs, bounds, observations, transitions,
        ...(childRule ? { rootChildExecTransition: childRule, observedNativeImageStarts, childExecTransitions } : {}),
        limitations: ["bounded observations only; transient or reparented-before-capture processes may be missed",
          "unrelated unpinned host processes are outside owned scope; new pinned native starts are counted globally",
          "declared artifact hashes identify sampled paths, not an attested in-memory executable image"] });
    },
  };
}
