function parseVersion(value) {
  const text = String(value || '').trim().replace(/^v/i, '');
  const match = text.match(/^(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  const numbers = match[1].split('.').map((part) => Number(part));
  if (numbers.some((part) => !Number.isSafeInteger(part))) return null;
  return { numbers, prerelease: match[2] ? match[2].split('.').map((part) => part.toLocaleLowerCase('en-US')) : [] };
}

export function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) return String(left).localeCompare(String(right), 'en', { numeric: true, sensitivity: 'base' });
  const length = Math.max(a.numbers.length, b.numbers.length, 3);
  for (let i = 0; i < length; i++) {
    const delta = (a.numbers[i] || 0) - (b.numbers[i] || 0);
    if (delta) return Math.sign(delta);
  }
  if (!a.prerelease.length && b.prerelease.length) return 1;
  if (a.prerelease.length && !b.prerelease.length) return -1;
  for (let i = 0; i < Math.max(a.prerelease.length, b.prerelease.length); i++) {
    const av = a.prerelease[i];
    const bv = b.prerelease[i];
    if (av === undefined) return -1;
    if (bv === undefined) return 1;
    const an = /^\d+$/.test(av) ? Number(av) : null;
    const bn = /^\d+$/.test(bv) ? Number(bv) : null;
    if (an !== null && bn !== null && an !== bn) return Math.sign(an - bn);
    if (an !== null && bn === null) return -1;
    if (an === null && bn !== null) return 1;
    if (av !== bv) return av < bv ? -1 : 1;
  }
  return 0;
}

function parseBoundedRange(range) {
  const value = String(range || '').trim();
  if (!value || value === '*') return [{ min: null, max: null, includeMin: false, includeMax: false }];
  const match = value.match(/^([[(])\s*([^,]*)\s*,\s*([^\])}]*)\s*([\])])$/);
  if (match) {
    return [{
      min: match[2].trim() || null,
      max: match[3].trim() || null,
      includeMin: match[1] === '[',
      includeMax: match[4] === ']',
    }];
  }
  const exact = value.match(/^\[([^\]]+)\]$/);
  if (exact) return [{ min: exact[1].trim(), max: exact[1].trim(), includeMin: true, includeMax: true }];
  const bare = value.match(/^(\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/);
  if (bare) return [{ min: bare[1], max: null, includeMin: true, includeMax: false }];
  return null;
}

export function parseNugetRange(value) {
  const source = String(value || '').trim();
  if (!source || source === '*') return [{ min: null, max: null, includeMin: false, includeMax: false }];
  const ranges = source.split('|').map(parseBoundedRange);
  return ranges.some((range) => range === null) ? null : ranges.flat();
}

export function versionMatchesRange(version, range) {
  const parsed = parseNugetRange(range);
  if (!parsed) return null;
  return parsed.some((interval) => {
    if (interval.min) {
      const delta = compareVersions(version, interval.min);
      if (delta < 0 || (delta === 0 && !interval.includeMin)) return false;
    }
    if (interval.max) {
      const delta = compareVersions(version, interval.max);
      if (delta > 0 || (delta === 0 && !interval.includeMax)) return false;
    }
    return true;
  });
}

export function highestVersion(versions) {
  return [...versions].sort((a, b) => compareVersions(b, a))[0] || null;
}

export function isVersionAffected(version, advisory) {
  const affected = Array.isArray(advisory.affected) ? advisory.affected : [];
  for (const packageInfo of affected) {
    if (Array.isArray(packageInfo.versions) && packageInfo.versions.includes(version)) return true;
    for (const range of packageInfo.ranges || []) {
      let introduced = null;
      for (const event of range.events || []) {
        if (event.introduced !== undefined) introduced = event.introduced;
        if (event.fixed !== undefined && introduced !== null) {
          if (compareVersions(version, introduced) >= 0 && compareVersions(version, event.fixed) < 0) return true;
          introduced = null;
        }
        if (event.last_affected !== undefined && introduced !== null) {
          if (compareVersions(version, introduced) >= 0 && compareVersions(version, event.last_affected) <= 0) return true;
          introduced = null;
        }
      }
      if (introduced !== null && compareVersions(version, introduced) >= 0) return true;
    }
  }
  return false;
}
