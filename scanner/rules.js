const REDACTION_PATTERNS = [
  /\b(github_pat_[A-Za-z0-9_]{20,})\b/g,
  /\b(gh[pousr]_[A-Za-z0-9_]{16,})\b/g,
  /\b(AKIA[0-9A-Z]{16})\b/g,
  /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
  /\b(glpat-[A-Za-z0-9_-]{20,})\b/g,
  /\b(npm_[A-Za-z0-9]{20,})\b/g,
  /\b(sk-[A-Za-z0-9_-]{20,})\b/g,
  /((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)(["']?)[^\s"';,}]+/gi,
];

export function redactText(value) {
  let output = String(value || '');
  output = output.replace(REDACTION_PATTERNS[0], '[REDACTED_GITHUB_TOKEN]');
  output = output.replace(REDACTION_PATTERNS[1], '[REDACTED_GITHUB_TOKEN]');
  output = output.replace(REDACTION_PATTERNS[2], '[REDACTED_AWS_KEY]');
  output = output.replace(REDACTION_PATTERNS[3], '[REDACTED_SLACK_TOKEN]');
  output = output.replace(REDACTION_PATTERNS[4], '[REDACTED_GITLAB_TOKEN]');
  output = output.replace(REDACTION_PATTERNS[5], '[REDACTED_NPM_TOKEN]');
  output = output.replace(REDACTION_PATTERNS[6], '[REDACTED_API_KEY]');
  output = output.replace(REDACTION_PATTERNS[7], '$1$2[REDACTED]');
  return output.slice(0, 500);
}

function evidence(file, line, text) {
  return {
    file: String(file.path || '').slice(0, 500),
    line,
    snippet: redactText(String(text || '').trim()),
  };
}

function addFinding(findings, finding) {
  const key = [finding.id, finding.evidence?.file, finding.evidence?.line].join('|');
  if (!findings.some((existing) => [existing.id, existing.evidence?.file, existing.evidence?.line].join('|') === key)) findings.push(finding);
}

function linesOf(file) {
  return file.text.split(/\r?\n/);
}

function lineMatches(lines, pattern) {
  const matches = [];
  for (let index = 0; index < lines.length; index++) {
    if (pattern.test(lines[index])) matches.push({ line: index + 1, text: lines[index] });
    pattern.lastIndex = 0;
  }
  return matches;
}

export function analyzePowerShellBehavior(files) {
  const findings = [];
  for (const file of files.filter((item) => item.kind === 'script')) {
    const lines = linesOf(file);
    const activeLines = lines.map((text) => text.trimStart()).map((text) => text.startsWith('#') ? '' : text);
    const fullText = activeLines.join('\n');

    for (const match of lineMatches(activeLines, /\b(?:password|passwd|secret|token|api[_-]?key)\s*=\s*["'][^"']{4,}["']/i)) {
      addFinding(findings, {
        id: 'PSG-SECRET-001',
        category: 'secret',
        severity: 'high',
        confidence: 'medium',
        title: 'Possible hard-coded credential',
        description: 'A credential-like variable appears to be assigned a literal value. Review the source; the matched value is redacted.',
        evidence: evidence(file, match.line, match.text),
        references: [],
      });
    }

    for (const match of lineMatches(activeLines, /\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i)) {
      addFinding(findings, {
        id: 'PSG-SECRET-002',
        category: 'secret',
        severity: 'high',
        confidence: 'high',
        title: 'Credential or private key pattern in source',
        description: 'The source contains a credential format commonly used by a public service. The matched value is redacted in published evidence.',
        evidence: evidence(file, match.line, match.text),
        references: [],
      });
    }

    const dynamicMatches = lineMatches(activeLines, /\b(?:invoke-expression|iex)\b|\[scriptblock\]\s*::\s*create|\$executioncontext\.invokecommand/i);
    for (const match of dynamicMatches) {
      addFinding(findings, {
        id: 'PSG-BEHAVIOR-001',
        category: 'behavior',
        severity: 'medium',
        confidence: 'low',
        title: 'Dynamic PowerShell code execution',
        description: 'Dynamic evaluation can make a script harder to inspect and may enable downloaded or constructed code to run.',
        evidence: evidence(file, match.line, match.text),
        references: [],
      });
    }

    const downloadMatches = lineMatches(activeLines, /\b(?:invoke-webrequest|invoke-restmethod|start-bitstransfer)\b|downloadstring|downloadfile|new-object\s+net\.webclient/i);
    const executionMatches = lineMatches(activeLines, /\b(?:invoke-expression|iex|start-process)\b|\[scriptblock\]\s*::\s*create|\.(?:invoke|dynamicinvoke)\s*\(/i);
    if (downloadMatches.length && executionMatches.length) {
      const first = downloadMatches[0];
      const second = executionMatches[0];
      addFinding(findings, {
        id: 'PSG-BEHAVIOR-002',
        category: 'behavior',
        severity: 'high',
        confidence: 'medium',
        title: 'Network retrieval combined with code execution',
        description: 'The same file contains both a network retrieval pattern and a dynamic execution pattern. This combination merits review and is not by itself proof of malicious intent.',
        evidence: evidence(file, first.line, first.text + '  …  ' + second.text),
        references: [],
      });
    }

    const decodeMatches = lineMatches(activeLines, /frombase64string|convert::frombase64string|-(?:encodedcommand|enc)\b|gzipstream|deflatestream/i);
    if (decodeMatches.length && dynamicMatches.length) {
      const match = decodeMatches[0];
      addFinding(findings, {
        id: 'PSG-BEHAVIOR-003',
        category: 'behavior',
        severity: 'medium',
        confidence: 'low',
        title: 'Encoded or compressed content used with dynamic execution',
        description: 'Encoded or compressed data is used alongside dynamic evaluation. This can appear in legitimate tooling; review the surrounding logic.',
        evidence: evidence(file, match.line, match.text),
        references: [],
      });
    }

    const persistenceMatches = lineMatches(activeLines, /register-scheduledtask|new-scheduledtask|currentversion\\run|startup\\s*folder|schtasks(?:\.exe)?\s+\/create/i);
    const credentialMatches = lineMatches(activeLines, /mimikatz|sekurlsa|credentialmanager|vaultcmd|cmdkey(?:\.exe)?\s+\/list/i);
    if (persistenceMatches.length && credentialMatches.length) {
      const match = persistenceMatches[0];
      addFinding(findings, {
        id: 'PSG-BEHAVIOR-004',
        category: 'behavior',
        severity: 'high',
        confidence: 'medium',
        title: 'Persistence and credential-access patterns in one file',
        description: 'A persistence mechanism and a credential-access indicator appear in the same file. Review intent and context before drawing conclusions.',
        evidence: evidence(file, match.line, match.text),
        references: [],
      });
    }

    if (/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/.test(fullText)) {
      const line = activeLines.findIndex((text) => /[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/.test(text));
      addFinding(findings, {
        id: 'PSG-BEHAVIOR-005',
        category: 'behavior',
        severity: 'medium',
        confidence: 'medium',
        title: 'Invisible or bidirectional Unicode characters',
        description: 'The source contains Unicode control characters that can obscure the visible order or appearance of code.',
        evidence: evidence(file, line + 1, activeLines[line]),
        references: [],
      });
    }
  }
  return findings;
}

const PSSA_RULES = new Map([
  ['PowerShellParseError', { severity: 'medium', confidence: 'high', title: 'PowerShell syntax could not be parsed' }],
  ['PSAvoidUsingAllowUnencryptedAuthentication', { severity: 'medium', confidence: 'high', title: 'Unencrypted authentication is enabled' }],
  ['PSAvoidUsingConvertToSecureStringWithPlainText', { severity: 'high', confidence: 'high', title: 'Plain text is converted to a secure string' }],
  ['PSAvoidUsingInvokeExpression', { severity: 'medium', confidence: 'low', title: 'Dynamic PowerShell evaluation is used' }],
  ['PSAvoidUsingPlainTextForPassword', { severity: 'high', confidence: 'medium', title: 'Plain text password parameter is declared' }],
  ['PSAvoidUsingUsernameAndPasswordParams', { severity: 'medium', confidence: 'medium', title: 'Separate username and password parameters are declared' }],
]);

export function normalizePSScriptAnalyzerFindings(results, files) {
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const findings = [];
  for (const result of results || []) {
    const rule = PSSA_RULES.get(result.ruleId);
    if (!rule) continue;
    const file = filesByPath.get(result.file) || { path: result.file || '', text: '' };
    const lineNumber = Math.max(1, Number(result.line) || 1);
    const sourceLine = file.text.split(/\r?\n/)[lineNumber - 1] || '';
    addFinding(findings, {
      id: 'PSSA-' + result.ruleId,
      category: 'static_rule',
      severity: rule.severity,
      confidence: rule.confidence,
      title: rule.title,
      description: redactText(result.message || rule.title),
      evidence: evidence(file, lineNumber, sourceLine),
      references: ['https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/rules/'],
    });
  }
  return findings;
}

export function redactFinding(finding) {
  return {
    ...finding,
    description: redactText(finding.description || ''),
    evidence: finding.evidence ? { ...finding.evidence, snippet: redactText(finding.evidence.snippet || '') } : null,
    references: (finding.references || []).filter((url) => {
      try { return new URL(url).protocol === 'https:'; } catch { return false; }
    }),
  };
}
