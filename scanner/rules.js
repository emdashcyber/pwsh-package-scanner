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

const PLACEHOLDER_CREDENTIAL_VALUES = new Set(['changeme', 'password']);

function stripComments(source) {
  let output = '';
  let quote = '';
  let blockComment = false;
  let lineComment = false;
  let hereStringEnd = '';
  for (let index = 0; index < source.length; index++) {
    const character = source[index];
    const next = source[index + 1] || '';
    if (lineComment) {
      if (character === '\n') { output += '\n'; lineComment = false; }
      else output += ' ';
      continue;
    }
    if (blockComment) {
      if (character === '#' && next === '>') { output += '  '; index++; blockComment = false; }
      else output += character === '\n' ? '\n' : ' ';
      continue;
    }
    if (hereStringEnd) {
      if ((index === 0 || source[index - 1] === '\n') && source.startsWith(hereStringEnd, index)) {
        output += hereStringEnd;
        index += hereStringEnd.length - 1;
        hereStringEnd = '';
        continue;
      }
      output += character;
      continue;
    }
    if (quote) {
      output += character;
      if (quote === '"' && character === '`' && next) { output += next; index++; continue; }
      if (character === quote) {
        if (next === quote) { output += next; index++; }
        else quote = '';
      }
      continue;
    }
    if (character === '<' && next === '#') { output += '  '; index++; blockComment = true; continue; }
    if (character === '#') { output += ' '; lineComment = true; continue; }
    if (character === '@' && (next === '"' || next === "'")) {
      const quoteChar = next;
      hereStringEnd = quoteChar + '@';
      output += character + next;
      index++;
      continue;
    }
    if (character === '"' || character === "'") quote = character;
    output += character;
  }
  return output;
}

function maskStrings(source) {
  let output = '';
  let quote = '';
  let hereStringEnd = '';
  for (let index = 0; index < source.length; index++) {
    const character = source[index];
    const next = source[index + 1] || '';
    if (hereStringEnd) {
      if ((index === 0 || source[index - 1] === '\n') && source.startsWith(hereStringEnd, index)) {
        output += hereStringEnd.replaceAll(/./g, ' ');
        index += hereStringEnd.length - 1;
        hereStringEnd = '';
        continue;
      }
      output += character === '\n' ? '\n' : ' ';
      continue;
    }
    if (quote) {
      output += character === '\n' ? '\n' : ' ';
      if (quote === '"' && character === '`' && next) { output += next === '\n' ? '\n' : ' '; index++; continue; }
      if (character === quote) {
        if (next === quote) { output += ' '; index++; }
        else quote = '';
      }
      continue;
    }
    if (character === '@' && (next === '"' || next === "'")) {
      hereStringEnd = next + '@';
      output += '  ';
      index++;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      output += ' ';
    } else output += character;
  }
  return output;
}

function credentialLiteralMatches(lines) {
  const matches = [];
  const pattern = /\b(?:password|passwd|secret|token|api[_-]?key)\s*=\s*(["'])([^"']*)\1/gi;
  for (let index = 0; index < lines.length; index++) {
    pattern.lastIndex = 0;
    for (const match of lines[index].matchAll(pattern)) {
      const value = match[2].trim();
      if (!value || PLACEHOLDER_CREDENTIAL_VALUES.has(value.toLocaleLowerCase('en-US')) || /\$[\w({]/.test(value)) continue;
      matches.push({ line: index + 1, text: lines[index] });
    }
  }
  return matches;
}

function relatedDownloadAndExecution(sourceLines, codeLines, dynamicMatches) {
  const downloads = lineMatches(codeLines, /\b(?:invoke-webrequest|invoke-restmethod|start-bitstransfer)\b|\.downloadstring\s*\(|\.downloadfile\s*\(|\bdownloadstring\s*\(|\bdownloadfile\s*\(/i)
    .map((match) => ({ ...match, text: sourceLines[match.line - 1] || '' }));
  if (!downloads.length) return null;

  const direct = lineMatches(codeLines, /\b(?:invoke-expression|iex)\s*\(?\s*\(*\s*(?:invoke-webrequest|invoke-restmethod|start-bitstransfer|[\w.$:]+\.downloadstring\s*\(|downloadstring\s*\()|\[scriptblock\]\s*::\s*create\s*\(\s*\(*\s*(?:invoke-webrequest|invoke-restmethod|[\w.$:]+\.downloadstring\s*\(|downloadstring\s*\()/i);
  if (direct.length) {
    const execution = dynamicMatches.find((match) => match.line === direct[0].line);
    if (execution) return { download: downloads.find((match) => match.line === direct[0].line) || downloads[0], execution };
  }

  const downloadedVariables = new Set();
  for (const match of lineMatches(codeLines, /\$([\w:]+)\s*=.*\b(?:invoke-webrequest|invoke-restmethod|start-bitstransfer)\b|\b(?:invoke-webrequest|invoke-restmethod|start-bitstransfer)\b.*?-(?:outfile|destination)\s+\$([\w:]+)/i)) {
    const variable = match.text.match(/\$([\w:]+)\s*=.*\b(?:invoke-webrequest|invoke-restmethod|start-bitstransfer)\b/i)?.[1]
      || match.text.match(/-(?:outfile|destination)\s+\$([\w:]+)/i)?.[1];
    if (variable) downloadedVariables.add(variable.toLocaleLowerCase('en-US'));
  }

  for (const execution of dynamicMatches) {
    const sink = codeLines[execution.line - 1] || '';
    if ([...downloadedVariables].some((variable) => new RegExp(`\\b${variable.replace(/[$]/g, '\\$')}\\b`, 'i').test(sink))) {
      return {
        download: downloads.find((download) => download.line <= execution.line) || downloads[0],
        execution,
      };
    }
  }

  const processLines = lineMatches(codeLines, /\bstart-process\b/i);
  for (const process of processLines) {
    const variable = process.text.match(/\bstart-process\b[^\r\n]*?(?:-filepath\s+)?\$([\w:]+)/i)?.[1];
    if (variable && downloadedVariables.has(variable.toLocaleLowerCase('en-US'))) {
      return {
        download: downloads.find((download) => download.line <= process.line) || downloads[0],
        execution: { ...process, text: sourceLines[process.line - 1] || '' },
      };
    }
  }
  return null;
}

function relatedEncodedExecution(sourceLines, codeLines, dynamicMatches) {
  const decoders = lineMatches(codeLines, /frombase64string|-(?:encodedcommand|enc)\b|gzipstream|deflatestream/i)
    .map((match) => ({ ...match, text: sourceLines[match.line - 1] || '' }));
  if (!decoders.length || !dynamicMatches.length) return null;
  for (const decoder of decoders) {
    const codeLine = codeLines[decoder.line - 1] || '';
    if (dynamicMatches.some((execution) => execution.line === decoder.line)
      && /(?:invoke-expression|\biex\b|\[scriptblock\]\s*::\s*create).*?(?:frombase64string|-(?:encodedcommand|enc)\b|gzipstream|deflatestream)|(?:frombase64string|-(?:encodedcommand|enc)\b|gzipstream|deflatestream).*?(?:invoke-expression|\biex\b|\[scriptblock\]\s*::\s*create)/i.test(codeLine)) return decoder;
    const variable = decoder.text.match(/\$([\w:]+)\s*=.*(?:frombase64string|gzipstream|deflatestream)/i)?.[1];
    if (!variable) continue;
    const execution = dynamicMatches.find((match) => new RegExp(`\\$${variable.replace(/[$]/g, '')}\\b`, 'i').test(codeLines[match.line - 1] || ''));
    if (execution) return decoder;
  }
  return null;
}

function isPlaceholderPlainTextConversion(file, result) {
  const lines = file.text.split(/\r?\n/);
  const first = Math.max(0, (Number(result.line) || 1) - 4);
  const last = Math.min(lines.length, (Number(result.endLine) || Number(result.line) || 1) + 4);
  const source = stripComments(file.text);
  const contextLines = stripComments(lines.slice(first, last).join('\n')).split('\n');
  const conversionLines = contextLines.filter((line) => /\bconvertto-securestring\b/i.test(line));
  if (!conversionLines.length) return false;
  const directPipeline = /^\s*(["'])\s*(changeme|password)\s*\1\s*\|\s*convertto-securestring\b/i;
  const directArgument = /(?:-string\s*(?:=\s*)?|\bconvertto-securestring\s+)(["'])\s*(changeme|password)\s*\1(?=\s|$)/i;
  if (conversionLines.some((line) => /-asplaintext\b/i.test(line)
    && (directPipeline.test(line) || directArgument.test(line)))) return true;

  const literalAssignments = new Map();
  const sourceLines = source.split('\n');
  const codeLines = maskStrings(source).split('\n');
  for (let index = 0; index < sourceLines.length; index++) {
    const masked = codeLines[index] || '';
    const original = sourceLines[index] || '';
    const assignment = masked.match(/\$([\w:]+)\s*=/);
    if (!assignment) continue;
    const literal = original.slice(assignment.index + assignment[0].length).match(/^\s*(["'])([^"']*)\1(?=\s*(?:;|$))/)?.[2]
      ?.trim().toLocaleLowerCase('en-US');
    if (literal && PLACEHOLDER_CREDENTIAL_VALUES.has(literal)) literalAssignments.set(assignment[1].toLocaleLowerCase('en-US'), literal);
  }
  return conversionLines.some((line) => {
    if (!/-asplaintext\b/i.test(line)) return false;
    const variables = [
      ...line.matchAll(/-string\s*(?:=\s*)?\$([\w:]+)/gi),
      ...line.matchAll(/\bconvertto-securestring\s+\$([\w:]+)/gi),
    ].map((match) => match[1].toLocaleLowerCase('en-US'));
    const pipelineInput = line.match(/\$([\w:]+)\s*\|\s*convertto-securestring\b/i)?.[1];
    if (pipelineInput) variables.push(pipelineInput.toLocaleLowerCase('en-US'));
    return variables.some((variable) => literalAssignments.has(variable));
  });
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
  for (const file of files.filter((item) => item.kind === 'script' && !/\.ps1xml$/i.test(item.path || ''))) {
    const sourceLines = linesOf(file);
    const commentFreeLines = stripComments(file.text).split(/\r?\n/);
    const codeLines = maskStrings(stripComments(file.text)).split(/\r?\n/);

    for (const match of credentialLiteralMatches(commentFreeLines)) {
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

    const tokenPattern = /\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b/i;
    for (const match of lineMatches(commentFreeLines, tokenPattern)) {
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

    const normalizedPemText = stripComments(file.text).replace(/\r\n?/g, '\n');
    const privateKeyPattern = /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----\s*([A-Za-z0-9+/=\s]{32,}?)\s*-----END \1-----/g;
    for (const match of normalizedPemText.matchAll(privateKeyPattern)) {
      const line = normalizedPemText.slice(0, match.index).split('\n').length;
      addFinding(findings, {
        id: 'PSG-SECRET-002',
        category: 'secret',
        severity: 'high',
        confidence: 'high',
        title: 'Credential or private key pattern in source',
        description: 'The source contains a complete PEM private-key block. Key material is redacted in published evidence.',
        evidence: evidence(file, line, '[REDACTED_PRIVATE_KEY_BLOCK]'),
        references: [],
      });
    }

    const dynamicMatches = lineMatches(codeLines, /\b(?:invoke-expression|iex)\b|\[scriptblock\]\s*::\s*create/i)
      .map((match) => ({ ...match, text: sourceLines[match.line - 1] || '' }));
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

    const relatedExecution = relatedDownloadAndExecution(sourceLines, codeLines, dynamicMatches);
    if (relatedExecution) {
      const first = relatedExecution.download;
      const second = relatedExecution.execution;
      addFinding(findings, {
        id: 'PSG-BEHAVIOR-002',
        category: 'behavior',
        severity: 'high',
        confidence: 'medium',
        title: 'Network retrieval combined with code execution',
        description: 'Downloaded content is passed to a dynamic execution mechanism. This pattern merits review and is not by itself proof of malicious intent.',
        evidence: evidence(file, first.line, first.text + '  …  ' + second.text),
        references: [],
      });
    }

    const encodedMatch = relatedEncodedExecution(sourceLines, codeLines, dynamicMatches);
    if (encodedMatch) {
      const match = encodedMatch;
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

    const persistenceMatches = lineMatches(codeLines, /register-scheduledtask|new-scheduledtask|currentversion\\run|startup\\s*folder|schtasks(?:\.exe)?\s+\/create/i);
    const credentialMatches = lineMatches(codeLines, /mimikatz|sekurlsa|credentialmanager|vaultcmd|cmdkey(?:\.exe)?\s+\/list/i);
    if (persistenceMatches.length && credentialMatches.length) {
      const match = { ...persistenceMatches[0], text: sourceLines[persistenceMatches[0].line - 1] || '' };
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

    if (codeLines.some((text) => /[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/.test(text))) {
      const line = codeLines.findIndex((text) => /[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/.test(text));
      addFinding(findings, {
        id: 'PSG-BEHAVIOR-005',
        category: 'behavior',
        severity: 'medium',
        confidence: 'medium',
        title: 'Invisible or bidirectional Unicode characters',
        description: 'The source contains Unicode control characters that can obscure the visible order or appearance of code.',
        evidence: evidence(file, line + 1, sourceLines[line]),
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
    if (result.ruleId === 'PSAvoidUsingConvertToSecureStringWithPlainText' && isPlaceholderPlainTextConversion(file, result)) continue;
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
