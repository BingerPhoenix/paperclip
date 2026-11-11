// Qualification-only construction and safe inspection. Never executes Codex.
import { createHash } from 'node:crypto';
import { resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

export const startupOverrides = Object.freeze({
  'features.shell_snapshot': false,
  'features.shell_snapshot_v2': false,
  allow_login_shell: false,
});
const required = Object.freeze({
  approval_policy: '"never"', 'features.apps': 'false', 'features.multi_agent': 'false',
  mcp_servers: '{}', 'sandbox_workspace_write.network_access': 'false',
  ...Object.fromEntries(Object.keys(startupOverrides).map(key => [key, 'false'])),
});
export const codexRelease = Object.freeze({ version: '0.167.0', tag: 'rust-v0.167.0',
  commit: '086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a',
  typedConfig: 'codex-rs/config/src/config_toml.rs',
  features: 'codex-rs/features/src/lib.rs',
  gate: 'codex-rs/core/src/session/session.rs',
  overrideInterface: 'codex-rs/utils/cli/src/config_override.rs' });

export function buildQualificationArgs({ fixtureDeclaration } = {}) {
  const args = ['--sandbox', 'read-only'];
  for (const [key, value] of Object.entries(required)) args.push('-c', `${key}=${value}`);
  if (fixtureDeclaration !== undefined) {
    if (typeof fixtureDeclaration !== 'string' || !isAbsolute(fixtureDeclaration) ||
        /[\x00-\x1f\x7f]/.test(fixtureDeclaration)) throw new Error('invalid_fixture_declaration');
    args.push('--qualification-declaration', fixtureDeclaration);
  }
  return args;
}

/** Inspect only supported official invocation args; return no argv or unknown values. */
export function inspectQualificationInvocation(commandArgs, { nonModelFixture = false } = {}) {
  const errors = new Set(), counts = Object.fromEntries(Object.keys(required).map(key => [key, 0]));
  let sandboxCount = 0, markerCount = 0, skipGitCount = 0, reasoningCount = 0;
  const valid = Array.isArray(commandArgs) && commandArgs.length >= 3 && commandArgs.length <= 128 &&
    commandArgs.every(v => typeof v === 'string' && v.length <= 4096 && !/[\x00-\x1f\x7f]/.test(v));
  const digest = valid ? createHash('sha256').update(JSON.stringify(commandArgs)).digest('hex') : null;
  if (!valid || commandArgs[0] !== 'exec' || commandArgs[1] !== '--json' || commandArgs.at(-1) !== '-') errors.add('unsupported_invocation_shape');
  if (valid) for (let i = 2; i < commandArgs.length - 1; i++) {
    const flag = commandArgs[i];
    if (flag === '-c') {
      const setting = commandArgs[++i];
      const match = typeof setting === 'string' ? /^([a-z_][a-z0-9_.]*)=(.*)$/.exec(setting) : null;
      if (!match || i >= commandArgs.length - 1) { errors.add('malformed_setting'); continue; }
      const [, key, value] = match;
      if (Object.hasOwn(required, key)) {
        counts[key]++;
        if (value !== required[key]) errors.add('conflicting_required_setting');
      } else if (key === 'model_reasoning_effort') {
        if (++reasoningCount !== 1 || value !== '"low"') errors.add('unsupported_reasoning_setting');
      } else errors.add('unsupported_setting');
    } else if (flag === '--sandbox') {
      sandboxCount++;
      if (commandArgs[++i] !== 'read-only' || i >= commandArgs.length - 1) errors.add('unsafe_sandbox');
    } else if (flag === '--qualification-declaration') {
      markerCount++;
      const path = commandArgs[++i];
      if (!nonModelFixture || typeof path !== 'string' || !isAbsolute(path) || i >= commandArgs.length - 1) errors.add('unexpected_fixture_marker');
    } else if (flag === '--skip-git-repo-check') {
      if (++skipGitCount > 1) errors.add('duplicate_flag');
    } else errors.add('unsupported_flag');
  }
  if (sandboxCount !== 1) errors.add('missing_or_duplicate_sandbox');
  for (const count of Object.values(counts)) if (count !== 1) errors.add('missing_or_duplicate_required_setting');
  if (markerCount !== (nonModelFixture ? 1 : 0)) errors.add('missing_or_duplicate_fixture_marker');
  const passed = errors.size === 0;
  return { schema: 'qualification-startup-invocation-v1', passed,
    errors: [...errors].sort(), argumentSha256: digest, requiredSettingCounts: counts,
    startup: passed ? { ...startupOverrides } : null,
    safety: passed ? { sandbox: 'read-only', approvalPolicy: 'never', apps: false,
      multiAgent: false, mcpEmpty: true, network: false, bypass: false } : null,
    fixtureMarkerPresent: markerCount === 1, laterConflictingSettings: !passed };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let data = '', exceeded = false;
  for await (const chunk of process.stdin) {
    data += chunk;
    if (data.length > 64 * 1024) { exceeded = true; break; }
  }
  let result;
  try {
    if (exceeded) throw new Error('input_limit');
    const input = JSON.parse(data);
    result = inspectQualificationInvocation(input.commandArgs, { nonModelFixture: input.nonModelFixture === true });
  } catch { result = { passed: false, errors: ['invalid_projection_input'] }; }
  process.stdout.write(JSON.stringify(result) + '\n');
  process.exitCode = result.passed ? 0 : 1;
}
