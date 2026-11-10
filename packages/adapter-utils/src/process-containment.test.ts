import { describe, it, expect, vi } from "vitest";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { runChildProcess, processAdmissionHolds } from "./server-utils.js";
import { processSnapshot, trackOwnedProcesses } from "./process-containment.js";
import { createProcessAccounting } from "./process-accounting.js";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

describe("bounded owned process cleanup", () => {
  it("reads executable metadata without exporting this owned fixture's argument canary", async () => {
    const child = spawn(process.execPath, ["-e", "setTimeout(()=>{},1000)", "ARGUMENT-CANARY-DO-NOT-EXPORT"], {
      stdio: "ignore",
    });
    try {
      const row = processSnapshot().find((r) => r.pid === child.pid);
      expect(row?.executable).toBeTruthy();
      expect(JSON.stringify(row)).not.toContain("ARGUMENT-CANARY-DO-NOT-EXPORT");
      expect(Object.keys(row!)).toEqual(["pid", "parent", "start", "state", "executable"]);
    } finally {
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      child.kill("SIGTERM"); await exited;
    }
  }, 2000);
  it("retains classified capture and bound accounting in official cleanup evidence", async () => {
    const at = new Date().toISOString();
    const accounting = createProcessAccounting({
      baseline: { observedAt: at, processes: [] }, sourceCommit: "a".repeat(40), contractSha256: "b".repeat(64),
      expectedNativeStarts: 0, rootLauncherPinId: "node",
      pins: [{ id: "node", path: process.execPath, classification: "node_helper",
        sha256: createHash("sha256").update(readFileSync(process.execPath)).digest("hex") }],
    });
    accounting.bindRoot({ runId: "owned-fixture-run", rootPid: 101 });
    let rows = [{ pid: 101, parent: 1, start: "root", state: "S", executable: process.execPath },
      { pid: 102, parent: 101, start: "child", state: "S", executable: process.execPath }];
    const tracker = trackOwnedProcesses({ pid: 101, exitCode: null, signalCode: null } as ChildProcess, {
      snapshot: () => rows,
      signal: (pid) => { rows = rows.filter((row) => row.pid !== pid); return true; },
    }, accounting);
    const result = await tracker.stop(0);
    expect(result.state).toBe("observed_gone");
    expect(result.accounting?.state).toBe("bounded_observed");
    expect(result.capturedIdentities.map((row) => row.classification)).toEqual(["known_launcher", "node_helper"]);
    expect(result.capturedIdentities.map((row) => row.pid)).toEqual([101, 102]);
  });
  it("retains known zombie executable history in cleanup without signalling dead identities", async () => {
    const accounting = createProcessAccounting({
      baseline: { observedAt: new Date().toISOString(), processes: [] }, sourceCommit: "a".repeat(40),
      contractSha256: "b".repeat(64), expectedNativeStarts: 0, rootLauncherPinId: "node",
      pins: [{ id: "node", path: process.execPath, classification: "node_helper",
        sha256: createHash("sha256").update(readFileSync(process.execPath)).digest("hex") }],
    });
    accounting.bindRoot({ runId: "zombie-fixture", rootPid: 101 });
    let rows: import("./process-containment.js").ProcessIdentity[] = [
      { pid: 101, parent: 1, start: "root", state: "S", executable: process.execPath },
      { pid: 102, parent: 101, start: "child", state: "S", executable: process.execPath }];
    const signal = vi.fn();
    const tracker = trackOwnedProcesses({ pid: 101, exitCode: null, signalCode: null } as ChildProcess,
      { snapshot: () => rows, signal }, accounting);
    rows = rows.map(row => ({ ...row, state: "Z", executable: null }));
    const result = await tracker.stop(0);
    expect(signal).not.toHaveBeenCalled(); expect(result.state).toBe("observed_gone");
    expect(result.accounting?.state).toBe("bounded_observed");
    expect(result.capturedIdentities.map(row => row.executable)).toEqual([process.execPath, process.execPath]);
    expect(result.capturedIdentities.map(row => row.classification)).toEqual(["known_launcher", "node_helper"]);
  });
  it("cleans a captured detached child after reparenting, within a five second fixture lifetime", async () => {
    const root = spawn(process.execPath, ["-e", `const{spawn}=require('node:child_process');const c=spawn(process.execPath,['-e','setTimeout(()=>{},5000)'],{detached:true,stdio:'ignore'});console.log(c.pid);setTimeout(()=>{},5000);`], { stdio: ["ignore", "pipe", "ignore"], detached: true });
    const tracker = trackOwnedProcesses(root);
    const childPid = await new Promise<number>((resolve) => root.stdout!.once("data", (data) => resolve(Number(String(data).trim()))));
    await new Promise((r) => setTimeout(r, 120));
    root.kill("SIGTERM");
    const result = await tracker.stop(200);
    expect(result.state).toBe("observed_gone");
    expect(result.observed).toBeGreaterThanOrEqual(2);
    expect(processSnapshot().some((p) => p.pid === childPid && !p.state.startsWith("Z"))).toBe(false);
  }, 6000);
  it("awaits bounded timeout cleanup and records its observed scope", async () => {
    const result=await runChildProcess("finite-timeout-fixture",process.execPath,["-e","setTimeout(()=>{},5000)"],{
      cwd:process.cwd(),env:{},timeoutSec:0.2,graceSec:1,onLog:async()=>{},
    });
    expect(result.timedOut).toBe(true); expect(result.processCleanup?.state).toBe("observed_gone");
    expect(result.processCleanup?.scope).toBe("sampled_pid_start_identity");
  },6000);
  it("returns a finite non-pass with timeout hold before denied cleanup and inherited pipes", async () => {
    let held=false; const original=process.kill;
    const denied=vi.spyOn(process,"kill").mockImplementation(()=>{
      expect(held).toBe(true);
      throw Object.assign(new Error("fixture signal denial"),{code:"EPERM"});
    });
    const start=Date.now();
    try {
      const result=await runChildProcess("finite-denied-pipe",process.execPath,["-e",
        "const{spawn}=require('node:child_process');spawn(process.execPath,['-e','setTimeout(()=>{},5000)'],{detached:true,stdio:['ignore','inherit','inherit']});console.log('partial-before-timeout');setTimeout(()=>process.exit(0),1000);"],{
        cwd:process.cwd(),env:{},timeoutSec:0.2,graceSec:1,onLog:async()=>{},onTimeout:async()=>{held=true;},
      });
      expect(Date.now()-start).toBeLessThan(3000); expect(held).toBe(true);
      expect(result.timedOut).toBe(true); expect(result.exitCode).toBe(null);
      expect(result.stdout).toContain("partial-before-timeout");
      expect(result.processCleanup?.state).toBe("unknown");
      expect(result.processCleanup?.errors).toContain("signal_denied_or_unknown");
    } finally { denied.mockRestore(); expect(process.kill).toBe(original); }
  },6000);
  it("fences a cancellation while asynchronous spawn preparation is pending", async () => {
    const id="finite-cancel-before-spawn"; let spawned=false;
    const pending=runChildProcess(id,process.execPath,["-e","process.exit(99)"],{
      cwd:process.cwd(),env:{},timeoutSec:1,graceSec:1,onLog:async()=>{},
      onSpawn:async()=>{spawned=true;},
    });
    // runChildProcess has begun async resolveSpawnTarget, but its spawn microtask
    // has not run. This is the same shared latch used by API cancellation.
    processAdmissionHolds.add(id);
    try { await expect(pending).rejects.toThrow("cancellation prevents"); expect(spawned).toBe(false); }
    finally { processAdmissionHolds.delete(id); }
  });
  it("preserves signal denial as unknown even when the root disappears", async () => {
    let rows = [{pid: 101,parent: 1,start: "same",state: "S"}];
    const tracker = trackOwnedProcesses({pid:101,exitCode:null,signalCode:null} as ChildProcess, {
      snapshot: () => rows,
      signal: () => { rows=[]; throw Object.assign(new Error("denied"), {code:"EPERM"}); },
    });
    const result = await tracker.stop(0);
    expect(result.state).toBe("unknown"); expect(result.errors).toContain("signal_denied_or_unknown");
  });
  it("does not signal a reused PID", async () => {
    let start="original"; const signals:number[]=[];
    const tracker=trackOwnedProcesses({pid:101,exitCode:null,signalCode:null} as ChildProcess, {
      snapshot:()=>[{pid:101,parent:1,start,state:"S"}], signal:(pid)=>{signals.push(pid);return true;},
    });
    start="replacement"; const result=await tracker.stop(0);
    expect(signals).toEqual([]); expect(result.state).toBe("observed_gone");
  });
  it("fails closed if metadata cannot be read", async () => {
    const tracker=trackOwnedProcesses({pid:101,exitCode:null,signalCode:null} as ChildProcess, {
      snapshot:()=>{throw new Error("unavailable");}, signal:()=>{throw new Error("must not signal");},
    });
    expect((await tracker.stop(0)).state).toBe("unknown");
  });
});
