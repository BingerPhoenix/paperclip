import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildLauncherDeclaration, validateLauncherDeclaration, verifyLauncherPreflight } from './qualification-launcher-preflight.mjs';

// Synthetic declared artifacts and accounting rows; no CLI/model/service run.
function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'launcher-closure-'));
  const write = (relative, content) => {
    const path = join(directory, relative); mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content, { mode: 0o755 }); return path;
  };
  const paths = {};
  for (const name of ['serviceNode', 'effectiveNode', 'env', 'native', 'codeMode']) paths[name] = write(name, `synthetic-${name}`);
  paths.codexScript = write('codex-script', '#!/usr/bin/env node\n// synthetic never executed\n');
  paths.codexCommand = join(directory, 'codex-link'); symlinkSync(paths.codexScript, paths.codexCommand);
  const contractFile = write('contract.md', 'synthetic frozen contract');
  write('packages/adapters/codex-local/src/server/execute.ts', 'const command = asString(config.command, "codex");\nrunAdapterExecutionTargetProcess(runId, runtimeExecutionTarget, command, args, {});');
  write('packages/adapters/codex-local/src/server/codex-args.ts', 'const args = ["exec", "--json"]; args.push(...extraArgs);');
  write('packages/adapters/codex-local/src/server/acp.ts', 'if (raw === "cli") return { engine: "cli", explicit: true };\nif (selection.explicit || selection.engine !== "acp") return selection;');
  write('packages/adapter-utils/src/execution-target.ts', 'return await runChildProcess(runId, command, args, {});');
  write('packages/adapter-utils/src/server-utils.ts', 'if (process.platform !== "win32") { return { command: executable, args }; }');
  const declaration = buildLauncherDeclaration({ sourceCommit: 'a'.repeat(40), contractFile, paths, root: directory });
  const effective = declaration.artifacts.find(item => item.id === 'homebrew-node');
  const service = declaration.artifacts.find(item => item.id === 'node22');
  const expectedRunId = 'official-nonmodel-run';
  const serviceIdentity = { pid: 500, start: 'service-start' };
  const accounting = { scope: 'bounded_sampled_process_accounting', state: 'bounded_observed', runId: expectedRunId,
    sourceCommit: declaration.sourceCommit, contractSha256: declaration.contractSha256, errors: [], expectedNativeStarts: 0, modelStartCount: 0,
    sampleCount: 3, baselineDigest: 'b'.repeat(64), transitions: [], root: { pid: 501, start: 'fixture-start' },
    baselineProcesses: [{ ...serviceIdentity, executable: service.canonicalPath, classification: 'node_helper' }],
    observations: [{ pid: 501, start: 'fixture-start', parent: 500, owned: true, runId: expectedRunId,
      firstObservedAt: '2026-11-11T03:00:00.100Z', lastObservedAt: '2026-11-11T03:00:00.200Z',
      executable: effective.canonicalPath, classification: 'known_launcher', pinId: 'homebrew-node', artifactSha256: effective.sha256 }],
    pins: declaration.artifacts.filter(item => item.classification !== 'declared_script').map(item => ({ id: item.id, path: item.canonicalPath, sha256: item.sha256, classification: item.classification })) };
  const receipt = { schema: 'qualification-launcher-fixture-v1', declarationSha256: declaration.declarationSha256,
    sourceCommit: declaration.sourceCommit, contractSha256: declaration.contractSha256,
    root: { pid: 501, parent: 500, executable: effective.canonicalPath }, cliPreparationSignature: 'fresh_cli_exec_json_stdin' };
  return { directory, paths, declaration, accounting, receipt, serviceIdentity, expectedRunId,
    officialInvocation: { adapterType: 'codex_local', engine: 'cli', transport: 'local', runId: expectedRunId, rootPid: 501,
      command: declaration.fixture.canonicalPath, commandSha256: declaration.fixture.sha256 },
    sourceCommit: declaration.sourceCommit, contractSha256: declaration.contractSha256,
    accountingOrigin: 'external_observer_bound_official_spawn' };
}
function run(check) {
  const value = fixture();
  try { check(value); } finally { rmSync(value.directory, { recursive: true, force: true }); }
}

function withEnv(value) {
  const node = value.accounting.observations[0];
  const env = value.declaration.artifacts.find(item => item.id === 'env-helper');
  value.accounting.observations.unshift({ ...node, executable: env.canonicalPath, artifactSha256: env.sha256,
    classification: 'declared_helper', pinId: env.id,
    firstObservedAt: '2026-11-11T03:00:00.000Z', lastObservedAt: '2026-11-11T03:00:00.050Z' });
  value.accounting.transitions.push({ kind: 'exec_change', pid: 501, start: 'fixture-start', previousStart: 'fixture-start',
    fromExecutable: env.canonicalPath, toExecutable: node.executable, observedAt: node.firstObservedAt });
  return value;
}

test('declared script/symlink/shebang and source mapping distinguish service from effective Node', () => run(value => {
  assert.equal(validateLauncherDeclaration(value.declaration), true);
  assert.equal(value.declaration.fixture.lifetimeMs, 3000);
  assert.equal(value.declaration.rootLauncherPinId, 'homebrew-node');
  assert.equal(value.declaration.installedCommand.shebang, '#!/usr/bin/env node');
  assert.equal(verifyLauncherPreflight(value).state, 'passed');
  assert.match(verifyLauncherPreflight(value).limitations[0], /not server-stored/);
}));

test('Node22-as-effective-launcher and unknown intended launchers reject admission', () => run(value => {
  for (const kind of ['node22', 'unknown']) {
    const candidate = structuredClone(value);
    const observation = candidate.accounting.observations[0];
    observation.executable = kind === 'node22' ? candidate.paths.serviceNode : '/unopened/unknown';
    observation.classification = kind === 'node22' ? 'known_launcher' : 'unknown';
    assert.equal(verifyLauncherPreflight(candidate).state, 'rejected');
    assert.ok(verifyLauncherPreflight(candidate).errors.includes('effective_launcher_mismatch'));
  }
}));

test('exact pinned pre-existing baseline native identity is retained without consuming a model start', () => run(value => {
  const native = value.declaration.artifacts.find(item => item.classification === 'native_model');
  value.accounting.baselineProcesses.push({ pid: 400, start: 'existing-native', parent: 1,
    executable: native.canonicalPath, classification: 'native_model' });
  value.accounting.observations.push({ pid: 400, start: 'existing-native', parent: 1, owned: false,
    runId: value.expectedRunId, executable: native.canonicalPath, classification: 'native_model',
    pinId: native.id, artifactSha256: native.sha256 });
  assert.equal(value.accounting.modelStartCount, 0);
  assert.equal(verifyLauncherPreflight(value).state, 'passed');
  const mutations = [
    candidate => { candidate.accounting.observations[1].pid = 401; },
    candidate => { candidate.accounting.observations[1].start = 'reused-start'; },
    candidate => { candidate.accounting.observations[1].executable = '/unopened/changed-native'; },
    candidate => { candidate.accounting.observations[1].artifactSha256 = 'c'.repeat(64); },
    candidate => { candidate.accounting.observations[1].pinId = 'unbound-native'; },
    candidate => { candidate.accounting.observations[1].owned = true; },
    candidate => { candidate.accounting.observations[1].runId = 'other-run'; },
    candidate => { candidate.accounting.baselineProcesses[1].classification = 'unknown'; },
    candidate => { candidate.accounting.transitions.push({ kind: 'exec_change', pid: 400, start: 'existing-native', previousStart: 'existing-native' }); },
    candidate => { candidate.accounting.transitions.push({ kind: 'pid_reuse', pid: 400, start: 'replacement', previousStart: 'existing-native' }); },
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(value); mutate(candidate);
    assert.equal(candidate.accounting.modelStartCount, 0);
    assert.equal(verifyLauncherPreflight(candidate).state, 'rejected');
  }
}));

test('unknown accounting, any model start, altered source/run/contract and wrong transport reject', () => run(value => {
  const mutations = [
    candidate => { candidate.accounting.errors = ['snapshot_gap']; },
    candidate => { candidate.accounting.modelStartCount = 1; },
    candidate => { candidate.accounting.observations.push({ classification: 'native_model' }); },
    candidate => { candidate.accounting.sourceCommit = 'c'.repeat(40); },
    candidate => { candidate.accounting.contractSha256 = 'c'.repeat(64); },
    candidate => { candidate.accounting.runId = 'other-run'; },
    candidate => { candidate.declaration.target.transport = 'remote'; },
    candidate => { candidate.accountingOrigin = 'official_stored_history'; },
    candidate => { candidate.serviceIdentity.pid = 123; },
    candidate => { candidate.accounting.pins = []; },
    candidate => { candidate.receipt.declarationSha256 = 'c'.repeat(64); },
    candidate => { candidate.officialInvocation.adapterType = 'process'; },
    candidate => { candidate.officialInvocation.engine = 'acp'; },
    candidate => { candidate.officialInvocation.transport = 'remote'; },
    candidate => { candidate.officialInvocation.command = candidate.paths.codexCommand; },
  ];
  for (const mutate of mutations) { const candidate = structuredClone(value); mutate(candidate); assert.equal(verifyLauncherPreflight(candidate).state, 'rejected'); }
}));

test('later known executable substitution cannot be hidden behind an earlier valid observation', () => run(value => {
  value.accounting.observations.push({ ...value.accounting.observations[0], executable: value.paths.serviceNode });
  assert.ok(verifyLauncherPreflight(value).errors.includes('effective_launcher_mismatch'));
}));

test('declared executable or installed script mutation rejects without opening observed paths', () => run(value => {
  value.accounting.observations[0].executable = '/unopened/ARGUMENT-CANARY-PRIVATE';
  writeFileSync(value.paths.effectiveNode, 'changed artifact');
  const result = verifyLauncherPreflight(value);
  assert.equal(result.state, 'rejected');
  assert.ok(result.errors.includes('declaration_invalid_or_changed'));
  assert.ok(!JSON.stringify(result).includes('ARGUMENT-CANARY-PRIVATE'));
}));

test('actual non-model fixture rejects a mismatched interpreter with finite sanitized Codex JSONL', () => run(value => {
  const declarationPath = join(value.directory, 'declaration.json');
  writeFileSync(declarationPath, JSON.stringify(value.declaration), { mode: 0o600 });
  const script = fileURLToPath(new URL('./qualification-launcher-preflight.mjs', import.meta.url));
  const child = spawnSync(process.execPath, [script, 'exec', '--json', '--qualification-declaration', declarationPath,
    '--unknown-fixture-flag', 'ARGUMENT-CANARY-PRIVATE', '-'], { timeout: 1000, maxBuffer: 8192, encoding: 'utf8' });
  assert.equal(child.error, undefined); assert.equal(child.status, 1);
  assert.deepEqual(JSON.parse(child.stdout.trim()), { type: 'error', message: 'launcher_preflight_rejected' });
  assert.ok(!`${child.stdout}${child.stderr}`.includes('ARGUMENT-CANARY-PRIVATE'));
  assert.equal(readFileSync(script, 'utf8').split('\n')[0], '#!/usr/bin/env node');
}));

// Independent matrix sealed BEFORE this phase change:
// 2a366384486e7fd0e59aef42aa33ed9631baefc1938c3561183a463b3c0e6cac.
// These test the final zero-model evaluator. Pending native monitoring remains
// root-owned and separate; env-only never passes this final evaluator.
const phaseCases = [
  ['node-only', true, value => value],
  ['exact-env-then-node', true, withEnv],
  ['env-only', false, value => { withEnv(value); value.accounting.observations.pop(); }],
  ['unknown-before-node', false, value => { withEnv(value); value.accounting.observations[0].classification = 'unknown'; }],
  ['env-path-or-hash-mismatch', false, value => { withEnv(value); value.accounting.observations[0].artifactSha256 = 'c'.repeat(64); }],
  ['env-pin-missing-or-wrong-class', false, value => { withEnv(value); value.accounting.pins = value.accounting.pins.filter(pin => pin.id !== 'env-helper'); }],
  ['pid-start-parent-run-mismatch', false, value => { withEnv(value); value.accounting.observations[0].start = 'other-start'; }],
  ['node-then-env-or-env-after-node', false, value => { withEnv(value); value.accounting.observations.reverse(); }],
  ['node-then-env-then-node', false, value => { withEnv(value); value.accounting.observations.unshift({ ...value.accounting.observations[1] }); }],
  ['env-or-node-root-reuse-or-reparent', false, value => { withEnv(value); value.accounting.transitions.push({ kind: 'reparent', pid: 501, start: 'fixture-start', previousStart: 'fixture-start' }); }],
  ['missing-or-extra-or-wrong-exec-transition', false, value => { withEnv(value); value.accounting.transitions = []; }],
  ['native-count-one-before-proven-node', false, value => { withEnv(value); value.accounting.observations.pop(); value.accounting.modelStartCount = 1; }],
  ['unknown-owned-or-extra-accounting-error', false, value => { withEnv(value); value.accounting.errors.push('snapshot_gap'); }],
  ['later-model-count-regression', false, value => { withEnv(value); value.accounting.observations.push({ ...value.accounting.observations[1], classification: 'native_model' }); value.accounting.modelStartCount = 0; }],
];
for (const [id, passes, mutate] of phaseCases) {
  test(`sealed launcher phase: ${id}`, () => run(value => {
    mutate(value);
    assert.equal(verifyLauncherPreflight(value).state, passes ? 'passed' : 'rejected');
  }));
}

test('env binding, chronology and transition variants fail without an unknown-helper exemption', () => run(value => {
  withEnv(value);
  const mutations = [
    candidate => { candidate.accounting.observations[0].executable = '/unopened/env'; },
    candidate => { candidate.accounting.observations[0].pinId = 'wrong-env-pin'; },
    candidate => { candidate.accounting.pins.find(pin => pin.id === 'env-helper').classification = 'node_helper'; },
    candidate => { candidate.accounting.observations[0].pid = 999; },
    candidate => { candidate.accounting.observations[0].parent = 999; },
    candidate => { candidate.accounting.observations[0].owned = false; },
    candidate => { candidate.accounting.observations[0].runId = 'other-run'; },
    candidate => { candidate.accounting.observations[0].lastObservedAt = '2026-11-11T03:00:00.150Z'; },
    candidate => { candidate.accounting.observations[1].firstObservedAt = 'invalid'; },
    candidate => { candidate.accounting.transitions.push({ ...candidate.accounting.transitions[0] }); },
    candidate => { candidate.accounting.transitions[0].fromExecutable = '/unopened/other'; },
    candidate => { candidate.accounting.transitions[0].previousStart = 'reused-start'; },
    candidate => { candidate.accounting.transitions[0].observedAt = '2026-11-11T03:00:00.150Z'; },
    candidate => { candidate.accounting.transitions[0].kind = 'pid_reuse'; },
  ];
  for (const mutate of mutations) { const candidate = structuredClone(value); mutate(candidate); assert.equal(verifyLauncherPreflight(candidate).state, 'rejected'); }
  // Sampling timestamps may meet exactly, but cannot overlap or reverse.
  value.accounting.observations[0].lastObservedAt = value.accounting.observations[1].firstObservedAt;
  assert.equal(verifyLauncherPreflight(value).state, 'passed');
}));
