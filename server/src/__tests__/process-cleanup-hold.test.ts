import { describe, it, expect } from "vitest";
import { hasProcessCleanupHold, processCleanupHoldMetadata } from "../services/process-cleanup-hold.js";
describe("durable process cleanup gate", () => {
  it("survives serialized restart and preserves other metadata", () => {
    const metadata=processCleanupHoldMetadata({retained:true},"run","cancellation_cleanup_requires_review");
    const restarted=JSON.parse(JSON.stringify({status:"idle",metadata}));
    expect(hasProcessCleanupHold(restarted)).toBe(true); expect(restarted.metadata.retained).toBe(true);
  });
  it("treats malformed present hold as held rather than allowing admission", () => {
    expect(hasProcessCleanupHold({metadata:{processCleanupHold:null}})).toBe(true);
    expect(hasProcessCleanupHold({metadata:{}})).toBe(false);
  });
});
