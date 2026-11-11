#!/usr/bin/env node
// Finite non-model replacement for a fresh local codex_local CLI invocation.
// It never imports/executes Codex, reads stdin, or exports arguments/environment.
// Root supplies --qualification-declaration PATH via fixture-only extraArgs and
// removes that marker when separately restoring the installed Codex command.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readlinkSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(import.meta.url);
const sourceRoot = resolve(dirname(here), '..');
const codexRoot = '/Users/shubbankarsingh/.nvm/versions/node/v22.22.3/lib/node_modules/@openai/codex';
const vendor = `${codexRoot}/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin`;
export const installedPaths = Object.freeze({
  serviceNode: '/Users/shubbankarsingh/.nvm/versions/node/v22.22.3/bin/node',
  effectiveNode: '/opt/homebrew/bin/node', env: '/usr/bin/env',
  codexCommand: '/Users/shubbankarsingh/.nvm/versions/node/v22.22.3/bin/codex',
  codexScript: `${codexRoot}/bin/codex.js`, native: `${vendor}/codex`, codeMode: `${vendor}/codex-code-mode-host`,
});
const sourceFiles = Object.freeze({
  execute: 'packages/adapters/codex-local/src/server/execute.ts',
  arguments: 'packages/adapters/codex-local/src/server/codex-args.ts',
  engine: 'packages/adapters/codex-local/src/server/acp.ts',
  transport: 'packages/adapter-utils/src/execution-target.ts',
  spawn: 'packages/adapter-utils/src/server-utils.ts',
});
const digest = data => createHash('sha256').update(data).digest('hex');
const safe = value => typeof value === 'string' && value.length > 0 && value.length <= 4096 &&
  !/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(value);
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const commit = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
const fail = code => { throw new Error(code); };
const fingerprint = stat => `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}:${stat.ctimeMs}`;
function artifact(id, path, classification, maxBytes = 512 * 1024 * 1024) {
  if (!safe(path) || !isAbsolute(path)) fail('invalid_declared_artifact');
  const canonicalPath = realpathSync(path), before = statSync(canonicalPath);
  if (!before.isFile() || before.size < 1 || before.size > maxBytes) fail('invalid_declared_artifact');
  const sha256 = digest(readFileSync(canonicalPath));
  if (fingerprint(before) !== fingerprint(statSync(canonicalPath))) fail('declared_artifact_changed');
  return { id, path, canonicalPath, classification, sha256 };
}
function declarationDigest(declaration) {
  const { declarationSha256: _ignored, ...body } = declaration;
  return digest(JSON.stringify(body));
}

/** Static source review anchors plus hashes, not an AST proof or runtime probe. */
function inspectPreparation(root) {
  const records = Object.entries(sourceFiles).map(([id, relative]) => artifact(id, resolve(root, relative), 'reviewed_source', 2 * 1024 * 1024));
  const text = id => readFileSync(records.find(item => item.id === id).canonicalPath, 'utf8');
  const checks = [
    /const command = asString\(config\.command, "codex"\)/.test(text('execute')),
    /runAdapterExecutionTargetProcess\(runId, runtimeExecutionTarget, command, args,/.test(text('execute')),
    /const args = \["exec", "--json"\]/.test(text('arguments')),
    /args\.push\(\.\.\.extraArgs\)/.test(text('arguments')),
    /if \(raw === "cli"\) return \{ engine: "cli", explicit: true \}/.test(text('engine')),
    /if \(selection\.explicit \|\| selection\.engine !== "acp"\) return selection/.test(text('engine')),
    /return await runChildProcess\(runId, command, args,/.test(text('transport')),
    /if \(process\.platform !== "win32"\) \{\s*return \{ command: executable, args \}/.test(text('spawn')),
  ];
  if (checks.some(check => !check)) fail('unsupported_adapter_preparation');
  return records;
}

export function buildLauncherDeclaration({ sourceCommit, contractFile, paths = installedPaths, root = sourceRoot, fixtureLifetimeMs = 3000 }) {
  if (!commit(sourceCommit) || !Number.isSafeInteger(fixtureLifetimeMs) || fixtureLifetimeMs < 50 || fixtureLifetimeMs > 3000) fail('invalid_declaration_binding');
  const contractPin = artifact('frozen-contract', contractFile, 'contract', 128 * 1024);
  const roles = [['serviceNode', 'node22', 'node_helper'], ['effectiveNode', 'homebrew-node', 'node_helper'],
    ['env', 'env-helper', 'declared_helper'], ['codexScript', 'installed-codex-script', 'declared_script'],
    ['native', 'codex-native', 'native_model'], ['codeMode', 'codex-code-mode-host', 'declared_helper']];
  const artifacts = roles.map(([role, id, classification]) => artifact(id, paths[role], classification));
  const script = artifacts.find(item => item.id === 'installed-codex-script');
  if (!safe(paths.codexCommand) || !isAbsolute(paths.codexCommand) || !lstatSync(paths.codexCommand).isSymbolicLink() ||
      realpathSync(paths.codexCommand) !== script.canonicalPath) fail('installed_command_symlink_mismatch');
  const shebang = readFileSync(script.canonicalPath, 'utf8').split('\n', 1)[0];
  if (shebang !== '#!/usr/bin/env node' || readFileSync(here, 'utf8').split('\n', 1)[0] !== shebang) fail('unsupported_script_shebang');
  const declaration = {
    schema: 'qualification-launcher-preflight-v1', sourceCommit, contractSha256: contractPin.sha256,
    contract: contractPin, preparation: inspectPreparation(root),
    target: { adapterType: 'codex_local', engine: 'cli', transport: 'local' },
    installedCommand: { path: paths.codexCommand, symlinkTarget: readlinkSync(paths.codexCommand), scriptPath: script.canonicalPath, shebang },
    rootLauncherPinId: 'homebrew-node', artifacts,
    fixture: { ...artifact('preflight-fixture', here, 'declared_script', 128 * 1024), lifetimeMs: fixtureLifetimeMs },
    limits: { expectedNativeStarts: 0, adapterTimeoutSec: 10, graceSec: 1, observationMs: 15000, cleanupMs: 5000 },
    limitations: ['Static installed-script/source mapping does not execute or attest Codex; actual service fixture evidence is required.',
      'The process fixture must use the same isolated service local codex_local CLI preparation; shell tests are insufficient.',
      'This evidence authorizes no native admission; root and independent review own that decision.'],
  };
  declaration.declarationSha256 = declarationDigest(declaration);
  validateLauncherDeclaration(declaration);
  return declaration;
}

export function validateLauncherDeclaration(declaration) {
  if (!declaration || declaration.schema !== 'qualification-launcher-preflight-v1' || !commit(declaration.sourceCommit) ||
      !hex(declaration.contractSha256) || !hex(declaration.declarationSha256) || declarationDigest(declaration) !== declaration.declarationSha256 ||
      declaration.target?.adapterType !== 'codex_local' || declaration.target.engine !== 'cli' || declaration.target.transport !== 'local' ||
      declaration.rootLauncherPinId !== 'homebrew-node' || declaration.limits?.expectedNativeStarts !== 0 ||
      declaration.limits.adapterTimeoutSec !== 10 || declaration.limits.graceSec !== 1 || declaration.limits.observationMs !== 15000 ||
      declaration.limits.cleanupMs !== 5000 || !Number.isSafeInteger(declaration.fixture?.lifetimeMs) ||
      declaration.fixture.lifetimeMs < 50 || declaration.fixture.lifetimeMs > 3000 || !Array.isArray(declaration.artifacts) ||
      declaration.artifacts.length !== 6 || !Array.isArray(declaration.preparation) || declaration.preparation.length !== 5) fail('invalid_launcher_declaration');
  const pins = [...declaration.artifacts, declaration.fixture, declaration.contract, ...declaration.preparation];
  if (declaration.contract?.sha256 !== declaration.contractSha256 || declaration.fixture?.canonicalPath !== here) fail('invalid_declaration_binding');
  if (new Set(pins.map(item => item?.id)).size !== pins.length) fail('duplicate_declared_artifact');
  for (const pin of pins) {
    if (!pin || !safe(pin.id) || !safe(pin.path) || !safe(pin.canonicalPath) || !isAbsolute(pin.path) || !isAbsolute(pin.canonicalPath) || !hex(pin.sha256)) fail('invalid_declared_artifact');
    const actual = artifact(pin.id, pin.path, pin.classification);
    if (actual.canonicalPath !== pin.canonicalPath || actual.sha256 !== pin.sha256) fail('declared_artifact_mismatch');
  }
  const find = id => declaration.artifacts.find(item => item.id === id);
  for (const [id, classification] of [['node22', 'node_helper'], ['homebrew-node', 'node_helper'], ['env-helper', 'declared_helper'],
    ['installed-codex-script', 'declared_script'], ['codex-native', 'native_model'], ['codex-code-mode-host', 'declared_helper']]) {
    if (find(id)?.classification !== classification) fail('invalid_artifact_classification');
  }
  if (find('node22').canonicalPath === find('homebrew-node').canonicalPath) fail('service_effective_node_not_distinct');
  const command = declaration.installedCommand;
  if (!safe(command?.path) || !isAbsolute(command.path) || command.shebang !== '#!/usr/bin/env node' ||
      realpathSync(command.path) !== find('installed-codex-script').canonicalPath ||
      command.scriptPath !== find('installed-codex-script').canonicalPath || readlinkSync(command.path) !== command.symlinkTarget ||
      readFileSync(command.scriptPath, 'utf8').split('\n', 1)[0] !== command.shebang ||
      readFileSync(declaration.fixture.canonicalPath, 'utf8').split('\n', 1)[0] !== command.shebang) fail('installed_command_symlink_mismatch');
  return true;
}

export function verifyLauncherPreflight({ declaration, accounting, receipt, officialInvocation, expectedRunId, serviceIdentity, sourceCommit, contractSha256, accountingOrigin }) {
  const errors = [];
  try { validateLauncherDeclaration(declaration); } catch { errors.push('declaration_invalid_or_changed'); }
  const artifacts = Array.isArray(declaration?.artifacts) ? declaration.artifacts : [];
  const observations = Array.isArray(accounting?.observations) ? accounting.observations : [];
  const expected = artifacts.find(item => item.id === 'homebrew-node');
  const root = accounting?.root;
  const rootObservations = observations.filter(item => item.pid === root?.pid && item.start === root?.start);
  const observed = rootObservations.at(-1);
  const service = artifacts.find(item => item.id === 'node22');
  const serviceBaseline = Array.isArray(accounting?.baselineProcesses) ? accounting.baselineProcesses.find(item => item.pid === serviceIdentity?.pid && item.start === serviceIdentity?.start) : null;
  const unexpectedNative = observations.some(item => {
    if (item.classification !== 'native_model') return false;
    const declared = artifacts.find(pin => pin.classification === 'native_model' && pin.canonicalPath === item.executable && pin.sha256 === item.artifactSha256);
    const pinned = Array.isArray(accounting?.pins) && accounting.pins.some(pin => pin.id === item.pinId && pin.path === item.executable &&
      pin.sha256 === item.artifactSha256 && pin.classification === 'native_model');
    const baseline = Array.isArray(accounting?.baselineProcesses) && accounting.baselineProcesses.some(row => row.pid === item.pid &&
      row.start === item.start && row.executable === item.executable && row.classification === 'native_model');
    const unchanged = Array.isArray(accounting?.transitions) && !accounting.transitions.some(change => change.pid === item.pid &&
      (change.start === item.start || change.previousStart === item.start) && (change.kind === 'exec_change' || change.kind === 'pid_reuse'));
    // Existing baseline models are retained by the observer, not new starts.
    // No broad exemption for unowned models or a caller-supplied zero count.
    return !declared || !pinned || !baseline || !unchanged || item.owned !== false || item.runId !== expectedRunId;
  });
  if (accountingOrigin !== 'external_observer_bound_official_spawn') errors.push('unsupported_accounting_origin');
  if (officialInvocation?.adapterType !== 'codex_local' || officialInvocation?.engine !== 'cli' || officialInvocation?.transport !== 'local' ||
      officialInvocation?.runId !== expectedRunId || officialInvocation?.rootPid !== root?.pid ||
      officialInvocation?.command !== declaration?.fixture?.canonicalPath || officialInvocation?.commandSha256 !== declaration?.fixture?.sha256) errors.push('official_preparation_binding_mismatch');
  if (!safe(expectedRunId) || !commit(sourceCommit) || !hex(contractSha256) || sourceCommit !== declaration?.sourceCommit ||
      contractSha256 !== declaration?.contractSha256 || accounting?.sourceCommit !== sourceCommit || accounting?.contractSha256 !== contractSha256) errors.push('source_contract_binding_mismatch');
  if (accounting?.runId !== expectedRunId || accounting?.state !== 'bounded_observed' || accounting?.scope !== 'bounded_sampled_process_accounting' ||
      accounting?.expectedNativeStarts !== 0 || accounting?.modelStartCount !== 0 || !Array.isArray(accounting?.errors) || accounting.errors.length ||
      !Number.isSafeInteger(accounting?.sampleCount) || accounting.sampleCount < 1 || !hex(accounting?.baselineDigest) ||
      !Array.isArray(accounting?.observations) || unexpectedNative || accounting.observations.some(item => item.owned && item.classification === 'unknown')) errors.push('accounting_not_zero_model_pass');
  if (!Number.isSafeInteger(serviceIdentity?.pid) || !safe(serviceIdentity?.start) || serviceBaseline?.executable !== service?.canonicalPath ||
      serviceBaseline?.classification !== 'node_helper' || observed?.parent !== serviceIdentity.pid) errors.push('service_node_binding_mismatch');
  for (const artifact of artifacts) {
    if (artifact.classification === 'declared_script') continue;
    if (!Array.isArray(accounting?.pins) || !accounting.pins.some(pin => pin.path === artifact.canonicalPath && pin.sha256 === artifact.sha256 && pin.classification === artifact.classification)) errors.push('accounting_artifact_pin_mismatch');
  }
  if (!Number.isSafeInteger(root?.pid) || root.pid < 1 || !safe(root?.start) || !observed?.owned || observed.runId !== expectedRunId ||
      observed.classification !== 'known_launcher' || observed.pinId !== 'homebrew-node' || observed.executable !== expected?.canonicalPath ||
      observed.artifactSha256 !== expected?.sha256 || rootObservations.some(item => item.classification !== 'known_launcher' ||
        item.executable !== expected?.canonicalPath || item.artifactSha256 !== expected?.sha256 || item.pinId !== 'homebrew-node')) errors.push('effective_launcher_mismatch');
  if (receipt?.schema !== 'qualification-launcher-fixture-v1' || receipt?.declarationSha256 !== declaration?.declarationSha256 ||
      receipt?.sourceCommit !== sourceCommit || receipt?.contractSha256 !== contractSha256 || receipt?.root?.pid !== root?.pid ||
      receipt?.root?.executable !== expected?.canonicalPath || receipt?.root?.parent !== serviceIdentity?.pid ||
      receipt?.cliPreparationSignature !== 'fresh_cli_exec_json_stdin') errors.push('fixture_receipt_mismatch');
  return { state: errors.length ? 'rejected' : 'passed', errors: [...new Set(errors)].sort(), sourceCommit, contractSha256,
    declarationSha256: declaration?.declarationSha256 ?? null, runId: expectedRunId, accountingOrigin,
    limitations: ['External observer evidence bound to official spawn, not server-stored accounting history.',
      'A passing non-model launcher preflight is not native admission or protected evaluator isolation.'] };
}

function fixtureDeclaration(args) {
  const marker = '--qualification-declaration';
  const index = args.indexOf(marker);
  if (args[0] !== 'exec' || args[1] !== '--json' || args.at(-1) !== '-' || index < 2 || index >= args.length - 2 ||
      args.lastIndexOf(marker) !== index || !safe(args[index + 1]) || !isAbsolute(args[index + 1]) || args.includes('resume')) fail('unsupported_fixture_cli_signature');
  const path = args[index + 1], stat = statSync(path);
  if (!stat.isFile() || stat.size < 1 || stat.size > 128 * 1024) fail('invalid_fixture_declaration_file');
  return JSON.parse(readFileSync(path, 'utf8'));
}

if (process.argv[1] && resolve(process.argv[1]) === here) {
  const started = performance.now();
  const deadline = setTimeout(() => process.exit(2), 5000);
  try {
    const declaration = fixtureDeclaration(process.argv.slice(2));
    validateLauncherDeclaration(declaration);
    const expected = declaration.artifacts.find(item => item.id === 'homebrew-node');
    if (realpathSync(process.execPath) !== expected.canonicalPath) fail('effective_launcher_mismatch');
    if (performance.now() - started > 1900) fail('fixture_preparation_deadline');
    const receipt = { schema: 'qualification-launcher-fixture-v1', declarationSha256: declaration.declarationSha256,
      sourceCommit: declaration.sourceCommit, contractSha256: declaration.contractSha256,
      root: { pid: process.pid, parent: process.ppid, executable: expected.canonicalPath },
      cliPreparationSignature: 'fresh_cli_exec_json_stdin' };
    process.stdout.write(`${JSON.stringify({ type: 'item.completed', item: { id: 'qualification-launcher-preflight', type: 'agent_message', text: JSON.stringify(receipt) } })}\n`);
    setTimeout(() => {
      process.stdout.write('{"type":"turn.completed","usage":{}}\n');
      process.exit(0);
    }, declaration.fixture.lifetimeMs);
  } catch {
    clearTimeout(deadline);
    process.stdout.write('{"type":"error","message":"launcher_preflight_rejected"}\n');
    process.exitCode = 1;
  }
}
