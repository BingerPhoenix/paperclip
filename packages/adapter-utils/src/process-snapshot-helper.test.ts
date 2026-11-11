import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll } from "vitest";
import { pinnedProcessSnapshot } from "./process-snapshot-helper.js";

const directory = mkdtempSync(join(tmpdir(), "snapshot-helper-test-"));
const path = join(directory, "owned-metadata-fixture");
const bytes = Buffer.from("owned non-executed fixture\n");
writeFileSync(path, bytes, { mode: 0o600 });
const sha = createHash("sha256").update(bytes).digest("hex");
afterAll(() => rmSync(directory, { recursive: true }));
const row = { pid: 123, parent: 1, start: "Tue Nov 10 18:05:50 2026", state: "R", executable: path };
const execute = (value: unknown) => (() => JSON.stringify(value)) as never;
describe("pinned metadata helper", () => {
  it("accepts only bounded safe process metadata", () => {
    expect(pinnedProcessSnapshot(path, sha, execute([row]))).toEqual([row]);
    expect(pinnedProcessSnapshot(path, sha, execute([{ ...row, executable: null }]))[0].executable).toBeNull();
  });
  it("rejects a changed executable before invoking it", () => {
    expect(() => pinnedProcessSnapshot(path, "0".repeat(64), (() => { throw new Error("must_not_execute"); }) as never))
      .toThrow("snapshot_helper_pin_mismatch");
  });
  it("rejects argv, environments, duplicate identities, invalid paths and malformed metadata", () => {
    for (const value of [[{ ...row, args: "forbidden" }], [{ ...row, env: {} }], [row, row],
      [{ ...row, executable: "node" }], [{ ...row, start: "bad\nstart" }], [], {}, [{ ...row, pid: -1 }]]) {
      expect(() => pinnedProcessSnapshot(path, sha, execute(value))).toThrow("malformed_snapshot_helper_metadata");
    }
  });
  it("propagates helper failure without a weaker fallback", () => {
    expect(() => pinnedProcessSnapshot(path, sha, (() => { throw new Error("metadata_unavailable"); }) as never))
      .toThrow("metadata_unavailable");
  });
});
