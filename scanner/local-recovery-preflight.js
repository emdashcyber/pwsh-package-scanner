import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { ARCHIVE_LIMITS } from './zip.js';

const REQUIRED_PSSCRIPTANALYZER_VERSION = '1.25.0';
const MAX_SIGNATURE_AGE_MS = 7 * 24 * 60 * 60 * 1000;

function run(command, args, { env = process.env, timeout = 15_000 } = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    env,
    timeout,
    maxBuffer: 2 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  return {
    code: result.status ?? 1,
    output: [result.stdout, result.stderr].filter(Boolean).join('\n').trim(),
  };
}

function ensurePowerShellAnalyzer(env) {
  const command = env.PWSH_PATH || 'pwsh';
  const modulePath = env.PSSCRIPTANALYZER_MODULE_PATH || env.PSModulePath || '';
  const probe = [
    "$module = Get-Module -ListAvailable -Name PSScriptAnalyzer |",
    `Where-Object { $_.Version -eq [version]'${REQUIRED_PSSCRIPTANALYZER_VERSION}' } |`,
    'Select-Object -First 1;',
    'if (-not $module) { exit 3 };',
    `Import-Module PSScriptAnalyzer -RequiredVersion ${REQUIRED_PSSCRIPTANALYZER_VERSION} -ErrorAction Stop;`,
    'if (-not (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) { exit 4 };',
    'Write-Output $module.ModuleBase',
  ].join(' ');
  const result = run(command, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', probe], {
    env: { ...env, ...(modulePath ? { PSModulePath: modulePath } : {}) },
  });
  if (result.code !== 0) {
    throw new Error('PowerShell 7 with PSScriptAnalyzer ' + REQUIRED_PSSCRIPTANALYZER_VERSION
      + ' is required for local recovery. ' + (result.output || 'The module was not found.'));
  }
  const moduleBase = result.output.split(/\r?\n/).at(-1)?.trim();
  if (!moduleBase) throw new Error('PowerShell did not return the PSScriptAnalyzer module path.');
  return {
    command,
    modulePath: env.PSSCRIPTANALYZER_MODULE_PATH || resolve(moduleBase, '..', '..'),
  };
}

function findClamdConfig(env) {
  const configured = env.CLAMAV_CLAMD_CONFIG || env.CLAMD_CONF;
  const candidates = configured ? [configured] : process.platform === 'darwin'
    ? ['/opt/homebrew/etc/clamav/clamd.conf', '/usr/local/etc/clamav/clamd.conf']
    : process.platform === 'win32'
      ? [join(env.ProgramData || 'C:\\ProgramData', 'ClamAV', 'clamd.conf')]
      : ['/etc/clamav/clamd.conf', '/etc/clamd.conf'];
  return candidates.find((candidate) => existsSync(candidate)) || null;
}

function readClamdLimits(configPath) {
  if (!configPath) return null;
  const config = readFileSync(configPath, 'utf8');
  const values = new Map();
  for (const line of config.split(/\r?\n/)) {
    const match = line.trim().match(/^(MaxFileSize|MaxScanSize)\s+([^\s#]+)/i);
    if (match) values.set(match[1].toLocaleLowerCase('en-US'), match[2]);
  }
  return {
    maxFileSize: parseSize(values.get('maxfilesize') || '100M'),
    maxScanSize: parseSize(values.get('maxscansize') || '400M'),
  };
}

function parseSize(value) {
  const match = String(value || '').trim().match(/^(\d+(?:\.\d+)?)\s*([kmgt]?)b?$/i);
  if (!match) return null;
  const power = { '': 0, k: 1, m: 2, g: 3, t: 4 }[match[2].toLocaleLowerCase('en-US')];
  return Number(match[1]) * (1024 ** power);
}

function databaseDirectories(env, clamdConfig) {
  const configured = env.CLAMAV_DATABASE_DIRECTORY;
  const candidates = [configured];
  if (clamdConfig) {
    const config = readFileSync(clamdConfig, 'utf8');
    const match = config.split(/\r?\n/).map((line) => line.trim())
      .find((line) => /^DatabaseDirectory\s+/i.test(line));
    if (match) candidates.push(match.replace(/^DatabaseDirectory\s+/i, '').trim());
  }
  if (process.platform === 'darwin') candidates.push('/opt/homebrew/var/lib/clamav', '/usr/local/var/lib/clamav');
  else if (process.platform === 'win32') candidates.push(join(env.ProgramData || 'C:\\ProgramData', 'ClamAV', 'Database'));
  else candidates.push('/var/lib/clamav');
  return [...new Set(candidates.filter(Boolean).map((item) => resolve(item)))];
}

function readDatabaseInfo(env, clamdConfig) {
  const entries = [];
  let activeDirectory = null;
  for (const directory of databaseDirectories(env, clamdConfig)) {
    if (!existsSync(directory)) continue;
    for (const name of readdirSync(directory)) {
      const match = name.match(/^(main|daily|bytecode)\.(?:cld|cvd)$/i);
      if (!match) continue;
      const file = join(directory, name);
      const result = run(env.SIGTOOL_PATH || 'sigtool', ['--info', file], { env });
      if (result.code !== 0) continue;
      const version = result.output.match(/^Version:\s*(.+)$/mi)?.[1]?.trim();
      const buildTime = result.output.match(/^Build time:\s*(.+)$/mi)?.[1]?.trim();
      if (version && buildTime) entries.push({ name: match[1].toLocaleLowerCase('en-US'), version, buildTime });
    }
    if (entries.length) {
      activeDirectory = directory;
      break;
    }
  }

  const fromEnvironment = env.CLAMAV_DATABASE_DATE
    ? env.CLAMAV_DATABASE_DATE.split(',').map((entry) => {
      const splitAt = entry.indexOf(':');
      return { name: splitAt < 0 ? 'daily' : entry.slice(0, splitAt), buildTime: splitAt < 0 ? entry : entry.slice(splitAt + 1) };
    })
    : [];
  const dailyDate = entries.find((entry) => entry.name === 'daily')?.buildTime
    || fromEnvironment.find((entry) => entry.name.toLocaleLowerCase('en-US') === 'daily')?.buildTime;
  const dailyVersion = entries.find((entry) => entry.name === 'daily')?.version
    || env.CLAMAV_DATABASE_VERSION?.split(',').find((entry) => entry.toLocaleLowerCase('en-US').startsWith('daily:'))?.split(':').at(1);
  if (!dailyDate || !dailyVersion) throw new Error('ClamAV daily signature database is missing or its date/version cannot be verified.');
  const dailyTimestamp = Date.parse(dailyDate);
  if (!Number.isFinite(dailyTimestamp)) throw new Error('ClamAV daily signature database has an unrecognized build date.');
  const age = Date.now() - dailyTimestamp;
  if (age < -24 * 60 * 60 * 1000 || age > MAX_SIGNATURE_AGE_MS) {
    throw new Error('ClamAV daily signatures must be no more than seven days old; run freshclam and retry.');
  }
  return {
    version: entries.length
      ? entries.map((entry) => entry.name + ':' + entry.version).join(',')
      : env.CLAMAV_DATABASE_VERSION,
    date: entries.length
      ? entries.map((entry) => entry.name + ':' + entry.buildTime).join(',')
      : env.CLAMAV_DATABASE_DATE,
    directory: activeDirectory || env.CLAMAV_DATABASE_DIRECTORY || null,
  };
}

export function prepareLocalRecoveryEnvironment(env = process.env) {
  const analyzer = ensurePowerShellAnalyzer(env);
  const command = env.CLAMAV_SCAN_COMMAND || 'clamdscan';
  const clamIsDaemon = basename(command).toLocaleLowerCase('en-US').startsWith('clamdscan');
  const clamdConfig = clamIsDaemon ? findClamdConfig(env) : null;
  if (clamIsDaemon && !clamdConfig) {
    throw new Error('clamdscan is selected, but its active clamd.conf was not found. Set CLAMAV_CLAMD_CONFIG to the daemon configuration file.');
  }
  const daemonConfigArgs = clamdConfig ? ['--config-file=' + clamdConfig] : [];
  const version = run(command, [...daemonConfigArgs, '--version'], { env });
  if (version.code !== 0 || !/\bClamAV\b/i.test(version.output)) {
    throw new Error('ClamAV is not ready: ' + (version.output || command + ' could not run.'));
  }

  if (clamIsDaemon) {
    const limits = readClamdLimits(clamdConfig);
    if (!limits || limits.maxFileSize < ARCHIVE_LIMITS.entryBytes || limits.maxScanSize < ARCHIVE_LIMITS.entryBytes) {
      throw new Error('ClamD MaxFileSize and MaxScanSize must each allow at least 35 MiB for the recovery scan.');
    }
    const ping = run(command, [...daemonConfigArgs, '--ping=3'], { env });
    if (ping.code !== 0) throw new Error('clamdscan cannot reach a working ClamD daemon: ' + (ping.output || 'ping failed.'));
  }

  const database = readDatabaseInfo(env, clamdConfig);
  const sampleDirectory = mkdtempSync(join(tmpdir(), 'gallery-clamav-preflight-'));
  try {
    const sampleFile = join(sampleDirectory, 'empty.bin');
    writeFileSync(sampleFile, Buffer.alloc(0), { mode: 0o600, flag: 'wx' });
    const scanArgs = [...daemonConfigArgs, '--no-summary', '--stdout'];
    if (clamIsDaemon) scanArgs.push('--fdpass');
    else if (basename(command).toLocaleLowerCase('en-US').startsWith('clamscan')) {
      scanArgs.push('--max-filesize=35M', '--max-scansize=150M');
      if (env.CLAMAV_DATABASE_DIRECTORY) scanArgs.push('--database=' + env.CLAMAV_DATABASE_DIRECTORY);
    }
    scanArgs.push(sampleFile);
    const scan = run(command, scanArgs, { env });
    if (scan.code !== 0) throw new Error('ClamAV could not scan a preflight file: ' + (scan.output || 'scan failed.'));
  } finally {
    rmSync(sampleDirectory, { recursive: true, force: true });
  }
  return {
    command,
    psscriptAnalyzerModulePath: analyzer.modulePath,
    clamDatabaseVersion: database.version,
    clamDatabaseDate: database.date,
    clamDatabaseDirectory: database.directory,
    clamdConfigPath: clamdConfig,
  };
}
