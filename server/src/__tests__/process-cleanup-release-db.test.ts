import { randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";
import { and, eq, sql } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { activityLog, agents, agentWakeupRequests, companies, createDb, heartbeatRuns } from "@paperclipai/db";
import { getEmbeddedPostgresTestSupport, startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres.js";
import { processCleanupEvidenceSha256, processCleanupHoldMetadata } from "../services/process-cleanup-hold.js";

const controls = vi.hoisted(() => ({
  snapshot: vi.fn(() => [{ pid: 1, parent: 0, start: "observer", state: "S" }]),
  afterAudit: null as null | (() => Promise<void>),
}));
vi.mock("@paperclipai/adapter-utils/process-containment", async () => ({
  ...await vi.importActual("@paperclipai/adapter-utils/process-containment"),
  processSnapshot: controls.snapshot,
}));
vi.mock("../services/activity-log.js", async () => {
  const actual = await vi.importActual<typeof import("../services/activity-log.js")>("../services/activity-log.js");
  return { ...actual, persistActivity: async (...args: Parameters<typeof actual.persistActivity>) => {
    const result = await actual.persistActivity(...args);
    await controls.afterAudit?.();
    return result;
  } };
});

const support = await getEmbeddedPostgresTestSupport();
const describeDb = support.supported ? describe : describe.skip;
type Db = ReturnType<typeof createDb>;

describeDb("transactional process cleanup release", () => {
  let db: Db;
  let temp: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
  beforeAll(async () => {
    temp = await startEmbeddedPostgresTestDatabase("paperclip-cleanup-release-");
    db = createDb(temp.connectionString);
    // Cold route transformation is setup, not a release operation deadline.
    await import("../services/agents.js");
    await import("../routes/agents.js");
  }, 30_000);
  afterEach(async () => {
    controls.afterAudit = null;
    controls.snapshot.mockReset().mockReturnValue([{ pid: 1, parent: 0, start: "observer", state: "S" }]);
    await db.delete(activityLog);
    await db.delete(heartbeatRuns);
    await db.delete(agentWakeupRequests);
    await db.delete(agents);
    await db.delete(companies);
  });
  afterAll(async () => temp?.cleanup());

  async function seed() {
    const company = await db.insert(companies).values({ name: "Release fixture", issuePrefix: `R${randomUUID().slice(0, 7)}` })
      .returning().then((rows) => rows[0]!);
    const runId = randomUUID();
    const metadata = processCleanupHoldMetadata({ keep: "retained" }, runId, "fixture_review");
    const agent = await db.insert(agents).values({ companyId: company.id, name: "Paused release fixture",
      role: "engineer", status: "paused", adapterType: "process", adapterConfig: { command: "fixture-before" },
      runtimeConfig: { heartbeat: { enabled: true, intervalSec: 60, wakeOnDemand: true, maxConcurrentRuns: 1 } }, metadata,
    }).returning().then((rows) => rows[0]!);
    const identity = { pid: 2147483646, start: "owned-fixture-identity", parent: 1,
      executable: "/declared/python", classification: "python_helper" };
    const cleanup = { scope: "sampled_pid_start_identity", state: "observed_gone", observed: 1, remaining: 0,
      errors: [], capturedIdentities: [identity], accounting: { scope: "bounded_sampled_process_accounting",
        state: "bounded_observed", runId, root: { pid: identity.pid, start: identity.start },
        baselineDigest: "a".repeat(64), baselineObservedAt: "2026-11-10T21:00:00.000Z",
        sourceCommit: "b".repeat(40), contractSha256: "c".repeat(64), expectedNativeStarts: 0,
        modelStartCount: 0, errors: [] } };
    await db.insert(heartbeatRuns).values({ id: runId, companyId: company.id, agentId: agent.id,
      status: "cancelled", processPid: identity.pid, finishedAt: new Date(), resultJson: { processCleanup: cleanup } });
    const input = { expectedHoldId: metadata.processCleanupHold.holdId, expectedRunId: runId,
      reviewedCleanupEvidenceSha256: processCleanupEvidenceSha256(cleanup), reviewNote: "Reviewed the official fixture evidence" };
    const { agentService } = await import("../services/agents.js");
    return { company, agent, runId, cleanup, input, service: agentService(db) };
  }
  async function appFor(actor: "board" | "agent", hook?: () => boolean, idle = true) {
    const { agentRoutes } = await import("../routes/agents.js");
    const app = express(); app.use(express.json());
    app.use((req, _res, next) => {
      req.actor = actor === "board" ? { type: "board", source: "local_implicit", userId: "fixture-board", isInstanceAdmin: true }
        : { type: "agent", source: "agent_key", agentId: randomUUID(), companyId: randomUUID(), runId: randomUUID() };
      next();
    });
    app.use("/api", agentRoutes(db, { onProcessCleanupHoldReleased: hook, isProcessCleanupRuntimeIdle: () => idle }));
    app.use((error: { status?: number; message: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(error.status ?? 500).json({ error: error.message });
    });
    return app;
  }

  it("requires final retained history for accounting-enabled runs before reviewed release", async () => {
    const f = await seed();
    await db.update(agents).set({ adapterConfig: { command: "fixture-before", processAccounting: {} } }).where(eq(agents.id, f.agent.id));
    const app = await appFor("board", () => true);
    expect((await request(app).post(`/api/agents/${f.agent.id}/process-cleanup-hold/release`).send(f.input)).status).toBe(409);
    expect((await f.service.getById(f.agent.id))?.metadata).toHaveProperty("processCleanupHold");
    await db.update(heartbeatRuns).set({ resultJson: { processCleanup: f.cleanup, processAccounting: f.cleanup.accounting } }).where(eq(heartbeatRuns.id, f.runId));
    expect((await request(app).post(`/api/agents/${f.agent.id}/process-cleanup-hold/release`).send(f.input)).status).toBe(200);
  });

  it("releases atomically with audit, leaves paused/off, then permits a separate nonsecret paused restoration", async () => {
    const f = await seed(); const app = await appFor("board", () => true);
    const release = await request(app).post(`/api/agents/${f.agent.id}/process-cleanup-hold/release`).send(f.input);
    expect(release.status).toBe(200);
    expect(release.body.agent).toEqual({ id: f.agent.id, status: "paused", heartbeat: { enabled: false, intervalSec: 0, wakeOnDemand: false } });
    expect(release.body).not.toHaveProperty("adapterConfig");
    const stored = await f.service.getById(f.agent.id);
    expect(stored?.metadata).toEqual({ keep: "retained" });
    expect(await db.select().from(activityLog).where(eq(activityLog.action, "agent.process_cleanup_hold.released"))).toHaveLength(1);
    const restore = await request(app).patch(`/api/agents/${f.agent.id}`).send({ adapterConfig: { command: "fixture-restored" } });
    expect(restore.status).toBe(200);
    expect((await f.service.getById(f.agent.id))?.status).toBe("paused");
    expect((await f.service.getById(f.agent.id))?.adapterConfig.command).toBe("fixture-restored");
    expect(await db.select().from(heartbeatRuns).where(and(eq(heartbeatRuns.agentId, f.agent.id), eq(heartbeatRuns.status, "running")))).toHaveLength(0);
    expect((await request(app).post(`/api/agents/${f.agent.id}/process-cleanup-hold/release`).send(f.input)).status).toBe(409);
  });
  it("denies agent callers and missing runtime wiring before mutation", async () => {
    const f = await seed();
    expect((await request(await appFor("agent", () => true)).post(`/api/agents/${f.agent.id}/process-cleanup-hold/release`).send(f.input)).status).toBe(403);
    expect((await request(await appFor("board")).post(`/api/agents/${f.agent.id}/process-cleanup-hold/release`).send(f.input)).status).toBe(503);
    expect((await f.service.getById(f.agent.id))?.metadata).toHaveProperty("processCleanupHold");
    expect(await db.select().from(activityLog)).toHaveLength(0);
  });
  it("gates terminal-but-still-finalizing and newly pending runtime work", async () => {
    const f = await seed();
    const response = await request(await appFor("board", () => true, false))
      .post(`/api/agents/${f.agent.id}/process-cleanup-hold/release`).send(f.input);
    expect(response.status).toBe(409);
    await expect(f.service.releaseProcessCleanupHold(f.agent.id, f.input, { actorId: "fixture-board" })).rejects.toMatchObject({ status: 409 });
    let calls = 0;
    await expect(f.service.releaseProcessCleanupHold(f.agent.id, f.input, {
      actorId: "fixture-board", runtimeIdle: () => ++calls === 1,
    })).rejects.toMatchObject({ status: 409 });
    expect((await f.service.getById(f.agent.id))?.metadata).toHaveProperty("processCleanupHold");
    expect(await db.select().from(activityLog)).toHaveLength(0);
  });
  it.each(["queued", "running"])("gates %s work with the hold and audit unchanged", async (status) => {
    const f = await seed();
    await db.insert(heartbeatRuns).values({ companyId: f.company.id, agentId: f.agent.id, status });
    await expect(f.service.releaseProcessCleanupHold(f.agent.id, f.input, { actorId: "fixture-board", runtimeIdle: () => true })).rejects.toMatchObject({ status: 409 });
    expect((await f.service.getById(f.agent.id))?.metadata).toHaveProperty("processCleanupHold");
    expect(await db.select().from(activityLog)).toHaveLength(0);
  });
  it("gates deferred wakeups and unresolved official cleanup", async () => {
    const f = await seed();
    await db.insert(agentWakeupRequests).values({ companyId: f.company.id, agentId: f.agent.id, source: "assignment", status: "deferred_issue_execution" });
    await expect(f.service.releaseProcessCleanupHold(f.agent.id, f.input, { actorId: "fixture-board", runtimeIdle: () => true })).rejects.toMatchObject({ status: 409 });
    await db.delete(agentWakeupRequests);
    const unknown = { ...f.cleanup, state: "unknown" };
    await db.update(heartbeatRuns).set({ resultJson: { processCleanup: unknown } }).where(eq(heartbeatRuns.id, f.runId));
    await expect(f.service.releaseProcessCleanupHold(f.agent.id, { ...f.input, reviewedCleanupEvidenceSha256: processCleanupEvidenceSha256(unknown) }, { actorId: "fixture-board", runtimeIdle: () => true })).rejects.toMatchObject({ status: 409 });
  });
  it("keeps a concurrently replaced hold rather than clearing the old generation", async () => {
    const f = await seed(); const replacement = processCleanupHoldMetadata({ keep: "new" }, f.runId, "replacement");
    let release!: Promise<unknown>;
    await db.transaction(async (tx) => {
      await tx.select().from(agents).where(eq(agents.id, f.agent.id)).for("update");
      await tx.update(agents).set({ metadata: replacement }).where(eq(agents.id, f.agent.id));
      release = f.service.releaseProcessCleanupHold(f.agent.id, f.input, { actorId: "fixture-board", runtimeIdle: () => true });
      // The locked row blocks the release until this replacement commits.
      await new Promise((resolve) => setTimeout(resolve, 40));
    });
    await expect(release).rejects.toMatchObject({ status: 409 });
    expect((await f.service.getById(f.agent.id))?.metadata).toEqual(replacement);
  });
  it("holds the work-table write barrier through commit; a later external insert is not prevented", async () => {
    const f = await seed();
    let releaseBarrier!: () => void; let auditReached!: () => void;
    const atAudit = new Promise<void>((resolve) => { auditReached = resolve; });
    const barrier = new Promise<void>((resolve) => { releaseBarrier = resolve; });
    controls.afterAudit = async () => { auditReached(); await barrier; };
    const release = f.service.releaseProcessCleanupHold(f.agent.id, f.input, { actorId: "fixture-board", runtimeIdle: () => true });
    await Promise.race([atAudit, release.then(() => { throw new Error("Release bypassed audit barrier"); }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Audit barrier timed out")), 2000))]);
    let inserted = false;
    const insertion = db.insert(heartbeatRuns).values({ companyId: f.company.id, agentId: f.agent.id, status: "queued" })
      .then(() => { inserted = true; });
    try {
      await new Promise((resolve) => setTimeout(resolve, 40));
      expect(inserted).toBe(false);
      expect((await f.service.getById(f.agent.id))?.metadata).toHaveProperty("processCleanupHold"); // uncommitted clear is invisible
    } finally { releaseBarrier(); }
    await release; await insertion;
    expect((await f.service.getById(f.agent.id))?.status).toBe("paused");
    expect(inserted).toBe(true); // future privileged DB writers are outside the admission guarantee
  });
  it("preserves a newer runtime fence and reports conflict after the old DB release commits", async () => {
    const f = await seed();
    const response = await request(await appFor("board", () => false)).post(`/api/agents/${f.agent.id}/process-cleanup-hold/release`).send(f.input);
    expect(response.status).toBe(409); expect(response.body.releasedHoldId).toBe(f.input.expectedHoldId);
    expect(await db.select().from(activityLog)).toHaveLength(1);
    expect((await f.service.getById(f.agent.id))?.status).toBe("paused");
  });
});
