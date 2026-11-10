import { execFileSync, type ChildProcess } from "node:child_process";

export interface ProcessIdentity { pid: number; parent: number; start: string; state: string }
export interface ProcessCleanupEvidence {
  scope: "sampled_pid_start_identity";
  state: "observed_gone" | "unknown";
  observed: number;
  remaining: number;
  errors: string[];
}
// Only process metadata is read: command arguments and environments can contain secrets.
export function processSnapshot(): ProcessIdentity[] {
  if (process.platform === "win32") throw new Error("unsupported_platform");
  return execFileSync("ps", ["-axo", "pid=,ppid=,lstart=,stat="], {
    encoding: "utf8", timeout: 1000, maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
  }).split("\n").flatMap((line) => {
    const m = line.trim().match(/^(\d+)\s+(\d+)\s+(.{24})\s+(\S+)$/);
    return m ? [{ pid: Number(m[1]), parent: Number(m[2]), start: m[3], state: m[4] }] : [];
  });
}

export function trackOwnedProcesses(child: ChildProcess, deps = {
  snapshot: processSnapshot,
  signal: (pid: number, signal: NodeJS.Signals) => process.kill(pid, signal),
}) {
  const known = new Map<number, ProcessIdentity>();
  const errors = new Set<string>();
  let rootStart: string | null = null;
  let stopping: Promise<ProcessCleanupEvidence> | null = null;
  const sample = () => {
    const rows = deps.snapshot();
    const root = rows.find((r) => r.pid === child.pid);
    if (!rootStart && root && child.exitCode === null && child.signalCode === null) rootStart = root.start;
    if (root && root.start === rootStart) known.set(root.pid, root);
    let changed = true;
    while (changed) {
      changed = false;
      for (const row of rows) {
        const parent = known.get(row.parent);
        // A parent PID reused after observation must never authorize a new child.
        if (parent && rows.some((r) => r.pid === parent.pid && r.start === parent.start)
            && !known.has(row.pid)) { known.set(row.pid, row); changed = true; }
      }
    }
    return rows;
  };
  const safeSample = () => {
    try { return sample(); } catch { errors.add("snapshot_unavailable"); return null; }
  };
  safeSample();
  const timer = setInterval(safeSample, 50); timer.unref();
  const live = (rows: ProcessIdentity[]) => [...known.values()].filter((id) =>
    rows.some((r) => r.pid === id.pid && r.start === id.start && !r.state.startsWith("Z")));
  return {
    dispose: () => clearInterval(timer),
    stop(graceMs: number): Promise<ProcessCleanupEvidence> {
      if (stopping) return stopping;
      stopping = (async () => {
        let rows = safeSample();
        if (!rootStart) errors.add("root_identity_unavailable");
        const send = (signal: NodeJS.Signals) => {
          rows = safeSample();
          if (!rows) return;
          // Children first. Only exact captured identities may receive a signal.
          for (const id of live(rows).sort((a,b) => Number(a.pid === child.pid) - Number(b.pid === child.pid))) {
            try { deps.signal(id.pid, signal); }
            catch (e) { if ((e as NodeJS.ErrnoException).code !== "ESRCH") errors.add("signal_denied_or_unknown"); }
          }
        };
        send("SIGTERM");
        const deadline = Date.now() + Math.max(0, Math.min(graceMs, 30_000));
        while (rows && live(rows).length && Date.now() < deadline) {
          await new Promise((resolve) => setTimeout(resolve, 25)); rows = safeSample();
        }
        if (rows && live(rows).length) send("SIGKILL");
        await new Promise((resolve) => setTimeout(resolve, 50));
        rows = safeSample(); clearInterval(timer);
        const remaining = rows ? live(rows).length : known.size;
        return { scope: "sampled_pid_start_identity", state: !errors.size && remaining === 0 ? "observed_gone" : "unknown",
          observed: known.size, remaining, errors: [...errors] };
      })();
      return stopping;
    },
  };
}
