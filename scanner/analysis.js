import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const analyzerScript = fileURLToPath(new URL('./analyzer.ps1', import.meta.url));
const ANALYZER_VERSION = '1.25.0';

function runProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { shell: false, windowsHide: true, ...options });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      if (!settled) {
        settled = true;
        reject(new Error('PowerShell static analysis exceeded the 45 second limit.'));
      }
    }, 45_000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (stdout.length > 4 * 1024 * 1024) child.kill('SIGKILL');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
      if (stderr.length > 2 * 1024 * 1024) child.kill('SIGKILL');
    });
    child.on('error', (error) => {
      clearTimeout(timeout);
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    child.on('close', (code) => {
      clearTimeout(timeout);
      if (settled) return;
      settled = true;
      if (code !== 0) reject(new Error(stderr.trim().slice(-2000) || 'PowerShell static analysis failed.'));
      else resolve({ stdout, stderr });
    });
  });
}

export async function runPSScriptAnalyzer(files, { enabled = true, pwsh = process.env.PWSH_PATH || 'pwsh' } = {}) {
  if (!enabled) return { findings: [], complete: true, analyzerVersion: null, powerShellVersion: null };
  const scripts = files.filter((file) => file.kind === 'script' && file.text.length > 0);
  if (!scripts.length) return { findings: [], complete: true, analyzerVersion: null, powerShellVersion: null };
  const root = await mkdtemp(join(tmpdir(), 'gallery-static-'));
  const mapping = [];
  try {
    for (let i = 0; i < scripts.length; i++) {
      const ext = (scripts[i].path.match(/\.(ps1|psm1|psd1|ps1xml|pssc)$/i) || [null, 'ps1'])[1].toLowerCase();
      const safeName = 'file-' + String(i + 1).padStart(5, '0') + '.' + ext;
      await writeFile(join(root, safeName), scripts[i].text, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      mapping.push({ safeName, originalPath: scripts[i].path });
    }
    const mapFile = join(root, 'file-map.json');
    await writeFile(mapFile, JSON.stringify(mapping), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    const result = await runProcess(pwsh, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-File', analyzerScript,
      '-InputRoot', root, '-MappingFile', mapFile,
    ], {
      cwd: root,
      env: {
        PATH: process.env.PATH || '/usr/bin:/bin',
        HOME: root,
        TMPDIR: root,
        LANG: 'C.UTF-8',
        POWERSHELL_TELEMETRY_OPTOUT: '1',
        ...(process.env.PSSCRIPTANALYZER_MODULE_PATH ? {
          PSModulePath: process.env.PSSCRIPTANALYZER_MODULE_PATH,
        } : {}),
        ...(process.platform === 'win32' ? {
          SystemRoot: process.env.SystemRoot || '',
          WINDIR: process.env.WINDIR || '',
          TEMP: root,
          TMP: root,
        } : {}),
      },
    });
    const line = result.stdout.split(/\r?\n/).find((item) => item.startsWith('PSANALYZER_JSON:'));
    if (!line) throw new Error('PowerShell analyzer returned no structured result.');
    const payload = JSON.parse(line.slice('PSANALYZER_JSON:'.length));
    const findings = Array.isArray(payload) ? payload : payload.findings;
    return {
      findings: Array.isArray(findings) ? findings : [],
      complete: true,
      analyzerVersion: payload.psscriptAnalyzerVersion || ANALYZER_VERSION,
      powerShellVersion: payload.powerShellVersion || null,
    };
  } catch (error) {
    return {
      findings: [],
      complete: false,
      analyzerVersion: null,
      error: String(error.message || error).slice(0, 1000),
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

export function getAnalyzerScriptName() {
  return basename(analyzerScript);
}
