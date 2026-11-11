# Proposed root-child exec accounting correction

Status: nonmodel-tested proposal only. Do not install, dispatch, release holds or
reinterpret earlier runs from this document. The stopped qualification remains
[nonpassing](https://github.com/BingerPhoenix/astray/blob/c73e161cac788a41ffa282b490ee573e2757539b/docs/operations/prompt3-results.md).
This change is based on source1cd13ad, kept separate from that original checkout
and the owner's installed package. No API endpoint, schema, auth or queue change.

## Diagnosis and confidence

The retained sample shows one direct child's identical PID/start/parent first
with the pinned Codex native image, then50ms later with the already-pinned
code-mode-helper image. A single official invocation was cancelled at count2.
The actual executable transition is observed. No second inference session is
established. A fork/pre-exec inherited-image interval is an inference consistent
with the sampling and version-matched normal helper-launch source.

Codex0.167.0 source commit086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a has two
helper-launch routes: `code-mode/src/remote_session/connection.rs` uses
`Command::new(host_program)`; `core/src/code_mode_host.rs` uses
`background_command(host_program)`, which is `Command::new` on non-Windows.
Both select a child helper with piped transport and kill-on-drop. InstallContext
resolves the companion/sibling code-mode host. The helper main runs the code-mode
host transport/runtime. The historical transport route and inference count are
not proven by these facts. Source30s IPC handshake timeouts are not permission
to defer native-image accounting for30s.

The existing observer counts the child's inherited native image immediately.
Its later helper exec does not remove the committed count. That is conservative
but conflates this normal possible child startup shape with a new model worker.
The original stopped result and failed hold are correct under its declared policy
and remain immutable. There is no retrospective count subtraction or budget refund.

## Explicit prospective policy

Default behavior is unchanged. Optional `processAccounting.rootChildExecTransition`:

```json
{
  "parentPinId": "codex-0.167.0-native",
  "helperPinId": "codex-code-mode-host",
  "deadlineMs": 250,
  "sourceCommit": "086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a",
  "sourceEvidenceSha256": "bind the reviewed exact launch-source evidence index"
}
```

The example hash text is intentionally invalid; it is not a runnable admission
configuration. An operator must bind actual source evidence and a fresh contract.
The constructor requires both existing exact pins/classes, valid provenance,
expectedNativeStarts1, a deadline1..1000ms and no unknown rule fields.

Only one never-before-seen direct child of the official root can be pending.
That exact root must already be counted/native in a prior complete snapshot and
remain unchanged. A bounded never-evicted host-PID history prevents an earlier
unowned/disappeared identity from masquerading as fresh; exhaustion rejects.

Keep all image observations, transitions and a separate raw-image count. A
pending journal is unknown/nonpassing; it cannot approve a result. Its deadline
starts at the first child frame and is checked against snapshot and monotonic
time. Both must be strictly below the declared deadline:249ms may resolve;
250ms rejects for a250ms window. Evidence reads expire it without new samples.
No timer or persistent queue is introduced.

Only the exact pinned helper target for the same physical/parent identity can
resolve. Unresolved, missing, incomplete, reused, reparented, unknown, late or
wrong-target observations reject permanently. Later target changes reject too.
A genuine second model is counted/rejected immediately when ineligible, or after
the finite deadline when initially indistinguishable. No passing interval is
granted while pending. A second native-image transition candidate rejects;
legitimate helper recovery may therefore be conservatively gated.

## Verification and remaining gates

Pure observer/parser regressions, independently chosen negative cases and owned
finite C substitute processes cover helper resolution, actual re-entry into a
second substitute program and a child that never transitions. No Codex/model
binary or service was invoked. Original failures and revised fixture receipts
are retained outside Git. Local typecheck/build and focused pinned-kernel
containment/retention checks passed. Default-ps retention reported an unknown
live executable and failed; that result was not changed into success. Older
five-second process cases, full monorepo and hosted checks remain unrun here.

This is bounded sampled metadata, not binary/in-memory attestation, hostile
process tracking, protected evaluator isolation or universal inference counting.
The one-model budget is unchanged. New native execution requires a new owner
budget and exact source/contract binding, isolated-instance nonmodel qualification
of policy ingestion/cleanup/hold behavior, and a reviewed supervisor that can
wait on the exact finite nonpassing pending state while rejecting every other
unknown. Existing strict supervisors do not understand this new pending state.
Never clear the original failed hold on the basis of this prospective proposal.
