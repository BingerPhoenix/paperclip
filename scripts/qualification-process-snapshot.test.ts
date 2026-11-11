import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import test from "node:test";
import { fileURLToPath } from "node:url";

type Identity = { pid: number; parent: number; start: string; state: string; executable: string | null };

test("Darwin libproc keeps actual executable identity when an owned Node process title changes", {
  skip: process.platform !== "darwin", timeout: 10000,
}, async () => {
  const directory = mkdtempSync(join(tmpdir(), "paperclip-darwin-snapshot-"));
  const binary = join(directory, "snapshot");
  try {
    execFileSync("/usr/bin/clang", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
      fileURLToPath(new URL("./qualification-process-snapshot.c", import.meta.url)), "-o", binary],
      { timeout: 5000, stdio: ["ignore", "pipe", "pipe"] });
    const child = spawn(process.execPath, ["-e", `
      process.stdout.write('ready\\n');
      const timer=setTimeout(()=>process.exit(0),3000);
      process.stdin.on('data',data=>{
        if(String(data).trim()==='finish'){clearTimeout(timer);process.exit(0);}
        process.title='node';process.stdout.write('changed:'+process.title+'\\n');
      });
    `, "ARGUMENT-CANARY-NOT-EXPORTED"], { stdio: ["pipe", "pipe", "ignore"] });
    const exited = once(child, "exit");
    const lines = createInterface({ input: child.stdout });
    const iterator = lines[Symbol.asyncIterator]();
    const snapshot = () => {
      const text = execFileSync(binary, [], { timeout: 1000, maxBuffer: 8 * 1024 * 1024, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      assert.ok(!text.includes("ARGUMENT-CANARY-NOT-EXPORTED"));
      const rows: Identity[] = JSON.parse(text);
      assert.ok(rows.length > 0 && rows.length <= 8192);
      assert.equal(new Set(rows.map(row => row.pid)).size, rows.length);
      for (const row of rows) {
        assert.deepEqual(Object.keys(row), ["pid", "parent", "start", "state", "executable"]);
        assert.ok(Number.isSafeInteger(row.pid) && row.pid > 0);
        assert.ok(Number.isSafeInteger(row.parent) && row.parent >= 0);
        assert.equal(row.start.length, 24); assert.match(row.state, /^[IRSTZ?]$/);
        assert.ok(row.executable === null || (row.executable.startsWith("/") && row.executable.length <= 4096));
      }
      return rows.find(row => row.pid === child.pid)!;
    };
    try {
      assert.equal((await iterator.next()).value, "ready");
      const before = snapshot();
      assert.ok(before); assert.equal(before.executable, realpathSync(process.execPath));
      child.stdin.write("change\n");
      assert.equal((await iterator.next()).value, "changed:node");
      const after = snapshot();
      assert.equal(after.pid, before.pid); assert.equal(after.start, before.start);
      assert.equal(after.parent, process.pid); assert.equal(after.executable, realpathSync(process.execPath));
      assert.equal(after.start.length, 24);
      const psStart = execFileSync("/bin/ps", ["-p", String(child.pid), "-o", "lstart="],
        { timeout: 1000, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      assert.equal(after.start, psStart);
      for (let sample = 0; sample < 4; sample++) {
        const repeated = snapshot();
        assert.equal(repeated.start, before.start);
        assert.equal(repeated.executable, realpathSync(process.execPath));
      }
    } finally {
      child.stdin.end("finish\n");
      await exited;
      lines.close();
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
