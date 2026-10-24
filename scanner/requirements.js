function tokenize(source) {
  const tokens = [];
  let index = 0;
  let line = 1;
  const push = (type, value, startLine) => tokens.push({ type, value, line: startLine });
  while (index < source.length) {
    const character = source[index];
    if (character === '\n') { line++; index++; continue; }
    if (/\s/.test(character)) { index++; continue; }
    if (character === '#') {
      while (index < source.length && source[index] !== '\n') index++;
      continue;
    }
    const startLine = line;
    if (character === "'" || character === '"') {
      const quote = character;
      index++;
      let value = '';
      let closed = false;
      while (index < source.length) {
        const current = source[index++];
        if (current === '\n') line++;
        if (current === '`' && quote === '"' && index < source.length) {
          value += source[index++];
          continue;
        }
        if (current === quote) {
          if (source[index] === quote) { value += quote; index++; continue; }
          closed = true;
          break;
        }
        value += current;
      }
      if (closed) push('string', value, startLine);
      else push('invalid', '', startLine);
      continue;
    }
    const two = source.slice(index, index + 2);
    if (['@{', '@('].includes(two)) {
      push('punctuation', two, startLine);
      index += 2;
      continue;
    }
    if ('=,;{}()'.includes(character)) {
      push('punctuation', character, startLine);
      index++;
      continue;
    }
    const start = index;
    while (index < source.length && !/[\s=,;{}()@#'\"]/.test(source[index])) index++;
    if (index === start) { index++; continue; }
    push('word', source.slice(start, index), startLine);
  }
  return tokens;
}

function assignment(tokens, name) {
  const wanted = name.toLocaleLowerCase('en-US');
  for (let index = 0; index < tokens.length - 1; index++) {
    if (tokens[index].value.toLocaleLowerCase('en-US') !== wanted || tokens[index + 1].value !== '=') continue;
    return tokens.slice(index + 2, expressionEnd(tokens, index + 2));
  }
  return [];
}

function expressionEnd(tokens, start) {
  const opening = new Map([['@(', ')'], ['@{', '}'], ['(', ')'], ['{', '}']]);
  const stack = [];
  for (let index = start; index < tokens.length; index++) {
    const value = tokens[index].value;
    if (opening.has(value)) stack.push(opening.get(value));
    else if (stack.length && value === stack.at(-1)) {
      stack.pop();
      if (!stack.length) return index + 1;
    } else if (!stack.length && (value === ';' || value === ',')) return index;
  }
  return tokens.length;
}

function nearestHashtableRange(tokens, index) {
  let open = -1;
  let depth = 0;
  for (let cursor = index; cursor >= 0; cursor--) {
    const value = tokens[cursor].value;
    if (value === '}') depth++;
    else if (value === '{' || value === '@{') {
      if (depth === 0) { open = cursor; break; }
      depth--;
    }
  }
  if (open < 0) return [0, tokens.length];
  depth = 0;
  for (let cursor = open; cursor < tokens.length; cursor++) {
    const value = tokens[cursor].value;
    if (value === '{' || value === '@{') depth++;
    else if (value === '}') {
      depth--;
      if (depth === 0) return [open, cursor + 1];
    }
  }
  return [open, tokens.length];
}

function propertyValue(tokens, name) {
  const wanted = name.toLocaleLowerCase('en-US');
  for (let index = 0; index < tokens.length - 1; index++) {
    if (tokens[index].value.toLocaleLowerCase('en-US') === wanted && tokens[index + 1].value === '=') {
      const value = tokens[index + 2];
      if (value?.type === 'string' || value?.type === 'word') return value.value;
    }
  }
  return '';
}

function versionRange(tokens, start, end) {
  const scope = tokens.slice(start, end);
  const exact = propertyValue(scope, 'RequiredVersion');
  if (exact) return '[' + exact + ']';
  const minimum = propertyValue(scope, 'ModuleVersion');
  const maximum = propertyValue(scope, 'MaximumVersion');
  if (minimum && maximum) return '[' + minimum + ',' + maximum + ']';
  if (minimum) return minimum;
  if (maximum) return '(,' + maximum + ']';
  return '*';
}

function extractSpecs(tokens, { packageName, relation, declarationSource, file, line, stringsAsModules = true }) {
  const specs = [];
  const moduleNameIndexes = new Set();
  const versionValueIndexes = new Set();
  for (let index = 0; index < tokens.length - 2; index++) {
    const key = tokens[index].value.toLocaleLowerCase('en-US');
    if (key !== 'modulename' || tokens[index + 1].value !== '=') continue;
    const nameToken = tokens[index + 2];
    if (!['string', 'word'].includes(nameToken.type) || nameToken.value.includes('$')) continue;
    const [scopeStart, scopeEnd] = nearestHashtableRange(tokens, index);
    const range = versionRange(tokens, scopeStart, scopeEnd);
    specs.push({
      name: nameToken.value,
      versionRange: range,
      relation,
      declarationSources: [declarationSource],
      file: file || null,
      line: line || tokens[index].line || null,
    });
    moduleNameIndexes.add(index + 2);
    for (let item = scopeStart; item < scopeEnd; item++) {
      if (['requiredversion', 'moduleversion', 'maximumversion'].includes(tokens[item].value.toLocaleLowerCase('en-US'))
        && tokens[item + 1]?.value === '=') versionValueIndexes.add(item + 2);
    }
  }
  if (stringsAsModules) {
    for (let index = 0; index < tokens.length; index++) {
      const token = tokens[index];
      if (token.type !== 'string' && token.type !== 'word') continue;
      if (moduleNameIndexes.has(index) || versionValueIndexes.has(index) || token.value.includes('$')) continue;
      const previous = tokens[index - 1]?.value;
      const next = tokens[index + 1]?.value;
      if (previous === '=' || next === '=') continue;
      if (token.type === 'word' && tokens.length > 1 && !['@(', ','].includes(previous)) continue;
      if (!/^[A-Za-z0-9_.-]+$/.test(token.value)) continue;
      specs.push({
        name: token.value,
        versionRange: '*',
        relation,
        declarationSources: [declarationSource],
        file: file || null,
        line: line || token.line || null,
      });
    }
  }
  const seen = new Set();
  return specs.filter((item) => {
    const key = item.name.toLocaleLowerCase('en-US') + '\0' + item.versionRange;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).map((item) => ({ ...item, package: packageName }));
}

export function parsePowerShellRequirements(files) {
  const requirements = [];
  const contains = [];
  for (const file of files || []) {
    if (file.kind !== 'script') continue;
    const extension = file.path.split('.').at(-1)?.toLocaleLowerCase('en-US');
    if (extension === 'psd1') {
      const tokens = tokenize(file.text);
      requirements.push(...extractSpecs(assignment(tokens, 'RequiredModules'), {
        relation: 'requires', declarationSource: 'RequiredModules', file: file.path,
      }));
      const moduleListTokens = assignment(tokens, 'ModuleList');
      for (const spec of extractSpecs(moduleListTokens, {
        relation: 'contains', declarationSource: 'ModuleList', file: file.path,
      })) contains.push(spec);
    }
    if (['ps1', 'psm1', 'psd1'].includes(extension)) {
      const lines = file.text.split(/\r?\n/);
      lines.forEach((text, index) => {
        const directive = text.match(/^\s*#Requires\b.*?-Modules\s+(.+)$/i);
        if (!directive) return;
        requirements.push(...extractSpecs(tokenize(directive[1]), {
          relation: 'requires', declarationSource: '#Requires -Modules', file: file.path, line: index + 1,
        }));
      });
    }
  }
  return { requirements, contains };
}
