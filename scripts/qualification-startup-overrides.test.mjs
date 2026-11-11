import test from 'node:test';
import assert from 'node:assert/strict';
import { buildQualificationArgs, inspectQualificationInvocation, startupOverrides } from './qualification-startup-overrides.mjs';
import { buildCodexExecArgs } from '../packages/adapters/codex-local/dist/server/codex-args.js';

const actual = (extraArgs = buildQualificationArgs()) => buildCodexExecArgs({ extraArgs, engine: 'cli', modelReasoningEffort: 'low' }).args;
test('actual adapter builder maps the three false overrides and all preserved safety settings', () => {
  const result = inspectQualificationInvocation(actual());
  assert.equal(result.passed, true); assert.deepEqual(result.startup, startupOverrides);
  assert.equal(result.safety.sandbox, 'read-only'); assert.equal(result.safety.approvalPolicy, 'never');
  assert.ok(Object.values(result.requiredSettingCounts).every(n => n === 1));
});
test('owned non-model marker is accepted only for that preflight', () => {
  const args = actual(buildQualificationArgs({ fixtureDeclaration: '/tmp/owned-declaration.json' }));
  assert.equal(inspectQualificationInvocation(args, { nonModelFixture: true }).passed, true);
  assert.equal(inspectQualificationInvocation(args).passed, false);
  assert.equal(inspectQualificationInvocation(actual(), { nonModelFixture: true }).passed, false);
});
for (const key of Object.keys(startupOverrides)) {
  test(`reject missing ${key}`, () => {
    const args = buildQualificationArgs(); const i = args.indexOf(`${key}=false`); args.splice(i - 1, 2);
    assert.equal(inspectQualificationInvocation(actual(args)).passed, false);
  });
  test(`reject conflicting or duplicate later ${key}`, () => {
    for (const value of ['true', 'false']) assert.equal(inspectQualificationInvocation(actual([...buildQualificationArgs(), '-c', `${key}=${value}`])).passed, false);
  });
}
test('reject alternate config/profile/aggregate bypasses and unsafe sandbox', () => {
  for (const suffix of [['--config', 'features.shell_snapshot=true'], ['--config=features.shell_snapshot=true'],
    ['-cfeatures.shell_snapshot=true'], ['--profile', 'other'], ['-c', 'features={shell_snapshot=true}'],
    ['--dangerously-bypass-approvals-and-sandbox'], ['--sandbox', 'workspace-write'], ['resume', 'old']]) {
    assert.equal(inspectQualificationInvocation(actual([...buildQualificationArgs(), ...suffix])).passed, false);
  }
});
test('reject every missing preserved setting and never leak unknown arguments', () => {
  const good = actual();
  for (const key of ['approval_policy', 'features.apps', 'features.multi_agent', 'mcp_servers', 'sandbox_workspace_write.network_access']) {
    const args = [...good], i = args.findIndex(x => x.startsWith(key + '=')); args.splice(i - 1, 2);
    assert.equal(inspectQualificationInvocation(args).passed, false);
  }
  const result = inspectQualificationInvocation(actual([...buildQualificationArgs(), '-c', 'unknown_secret=ARGUMENT-CANARY']));
  assert.equal(result.passed, false); assert.ok(!JSON.stringify(result).includes('ARGUMENT-CANARY'));
});
test('reject malformed invocations, nonstring input and missing terminator', () => {
  for (const args of [null, [], ['exec', '--json', '-c', '-'], ['exec', '--json', ...buildQualificationArgs()],
    [...actual(), 'later'], ['exec', '--json', null, '-']]) assert.equal(inspectQualificationInvocation(args).passed, false);
});
