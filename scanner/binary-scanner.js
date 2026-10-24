import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { mapLimit, safeString, sha256 } from './util.js';

const versionCache = new Map();

function run(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      shell: false,
      windowsHide: true,
      env: {
        PATH: process.env.PATH || '/usr/bin:/bin',
        HOME: cwd,
        TMPDIR: cwd,
        TEMP: cwd,
        LANG: 'C.UTF-8',
        CLAMAV_DATABASE_VERSION: process.env.CLAMAV_DATABASE_VERSION || '',
        CLAMAV_DATABASE_DATE: process.env.CLAMAV_DATABASE_DATE || '',
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout = (stdout + chunk).slice(-16_384); });
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-16_384); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

function parseVersion(text) {
  const match = String(text).match(/ClamAV\s+([^/\s]+)(?:\/([^/\s]+)\/([^\r\n]+))?/i);
  return {
    engineVersion: match?.[1] || null,
    databaseVersion: match?.[2] || process.env.CLAMAV_DATABASE_VERSION || null,
    databaseDate: match?.[3]?.trim() || process.env.CLAMAV_DATABASE_DATE || null,
  };
}

async function getToolVersion(command, workingDirectory) {
  const cached = versionCache.get(command);
  if (cached) return cached;
  const result = await run(command, ['--version'], workingDirectory);
  if (result.code !== 0) throw new Error(result.stderr.trim() || 'ClamAV version query failed.');
  const parsed = parseVersion(result.stdout || result.stderr);
  if (!parsed.engineVersion) throw new Error('ClamAV returned an unrecognized version string.');
  versionCache.set(command, parsed);
  return parsed;
}

async function scanOne(binary, index, command) {
  const root = await mkdtemp(join(tmpdir(), 'gallery-binary-'));
  try {
    const file = join(root, 'artifact-' + String(index + 1).padStart(5, '0') + '.bin');
    await writeFile(file, binary.content, { mode: 0o600, flag: 'wx' });
    const versions = await getToolVersion(command, root);
    const args = ['--no-summary', '--stdout'];
    if (basename(command).toLocaleLowerCase('en-US').includes('clamdscan')) args.push('--fdpass');
    args.push(file);
    const result = await run(command, args, root);
    const output = (result.stdout + '\n' + result.stderr).trim();
    if (result.code === 0) return { status: 'clean', signature: null, ...versions };
    if (result.code === 1) {
      const found = output.match(/:\s*(.*?)\s+FOUND\s*$/m);
      return { status: 'match', signature: safeString(found?.[1] || 'ClamAV signature match', 200), ...versions };
    }
    return {
      status: 'error',
      signature: null,
      ...versions,
      error: safeString(output || 'ClamAV scan failed with exit code ' + result.code + '.', 500),
    };
  } catch (error) {
    return {
      status: 'error',
      signature: null,
      engineVersion: null,
      databaseVersion: null,
      databaseDate: null,
      error: safeString(error.message || error, 500),
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

export async function scanBinaryEntries(binaries, {
  command = process.env.CLAMAV_SCAN_COMMAND || 'clamscan',
  scanner = null,
  concurrency = 2,
} = {}) {
  const rows = await mapLimit(binaries || [], concurrency, async (binary, index) => {
    const hash = sha256(binary.content);
    let clamav;
    try {
      clamav = scanner ? await scanner(binary, index) : await scanOne(binary, index, command);
    } catch (error) {
      clamav = { status: 'error', error: safeString(error.message || error, 500) };
    }
    return {
      path: binary.path,
      size: binary.size,
      sha256: hash,
      virusTotalSearchUrl: 'https://www.virustotal.com/gui/search/' + hash,
      clamav: {
        status: ['clean', 'match', 'error'].includes(clamav?.status) ? clamav.status : 'error',
        signature: safeString(clamav?.signature || '', 200) || null,
        engineVersion: safeString(clamav?.engineVersion || '', 80) || null,
        databaseVersion: safeString(clamav?.databaseVersion || '', 80) || null,
        databaseDate: safeString(clamav?.databaseDate || '', 120) || null,
        ...(clamav?.error ? { error: safeString(clamav.error, 500) } : {}),
      },
    };
  });
  return {
    binaries: rows,
    complete: rows.every((row) => row.sha256 && ['clean', 'match'].includes(row.clamav.status)),
  };
}

export function clearClamAvVersionCache() {
  versionCache.clear();
}
