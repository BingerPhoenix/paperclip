import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import type { ProcessIdentity } from "./process-containment.js";

/** Optional operator-pinned metadata program. It must never return argv or env. */
export function pinnedProcessSnapshot(path: string, sha256: string,
  execute: typeof execFileSync = execFileSync): ProcessIdentity[] {
  if (!isAbsolute(path) || !/^[a-f0-9]{64}$/.test(sha256)) throw new Error("invalid_snapshot_helper_pin");
  const canonical = realpathSync(path);
  const before = statSync(canonical);
  if (!before.isFile() || before.size > 1024 * 1024 ||
      createHash("sha256").update(readFileSync(canonical)).digest("hex") !== sha256) {
    throw new Error("snapshot_helper_pin_mismatch");
  }
  const after = statSync(canonical);
  if (realpathSync(path) !== canonical || before.ino !== after.ino || before.dev !== after.dev ||
      before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
    throw new Error("snapshot_helper_changed");
  }
  const output = execute(canonical, [], { encoding: "utf8", timeout: 1000,
    maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
  const final = statSync(canonical);
  if (realpathSync(path) !== canonical || after.ino !== final.ino || after.dev !== final.dev ||
      after.size !== final.size || after.mtimeMs !== final.mtimeMs || after.ctimeMs !== final.ctimeMs) {
    throw new Error("snapshot_helper_changed");
  }
  const rows: unknown = JSON.parse(String(output));
  const safe = (s: unknown, max: number): s is string => typeof s === "string" && s.length > 0 &&
    s.length <= max && !/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(s);
  if (!Array.isArray(rows) || !rows.length || rows.length > 8192 || !rows.every((r) =>
    r && typeof r === "object" && Object.keys(r).sort().join(",") === "executable,parent,pid,start,state" &&
    Number.isSafeInteger(r.pid) && r.pid > 0 && Number.isSafeInteger(r.parent) && r.parent >= 0 &&
    safe(r.start, 128) && safe(r.state, 32) &&
    (r.executable === null || (safe(r.executable, 4096) && isAbsolute(r.executable)))) ||
    new Set(rows.map((r) => r.pid)).size !== rows.length) throw new Error("malformed_snapshot_helper_metadata");
  return rows as ProcessIdentity[];
}
