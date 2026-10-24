const FEED_FIELDS = [
  'Id', 'Version', 'Title', 'Summary', 'Description', 'Authors', 'Owners', 'Tags',
  'ProjectUrl', 'Published', 'LastUpdated', 'IsLatestVersion',
  'IsAbsoluteLatestVersion', 'PackageSize', 'PackageHash', 'PackageHashAlgorithm',
  'Dependencies',
];

function decodeXmlText(value) {
  return String(value)
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#([0-9]+);/g, (_, number) => String.fromCodePoint(Number.parseInt(number, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function readElement(xml, name) {
  const safeName = name.replace(/[.*+?^$()|[\]\\]/g, '\\$&');
  const pattern = new RegExp('<(?:(?:[A-Za-z_][\\w.-]*):)?' + safeName + '(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:(?:[A-Za-z_][\\w.-]*):)?' + safeName + '\\s*>');
  const match = xml.match(pattern);
  return match ? decodeXmlText(match[1].replace(/<[^>]+>/g, '').trim()) : '';
}

function parseAttributes(source) {
  const attributes = {};
  const pattern = /([A-Za-z_:][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  for (const match of source.matchAll(pattern)) {
    const key = match[1].split(':').at(-1).toLocaleLowerCase('en-US');
    attributes[key] = decodeXmlText(match[2] ?? match[3] ?? '');
  }
  return attributes;
}

function parseLinkHeader(xml) {
  const pattern = /<(?:[A-Za-z_][\w.-]*:)?link\b([^>]*?)\/?>/gi;
  for (const match of xml.matchAll(pattern)) {
    const attributes = parseAttributes(match[1]);
    if (attributes.rel?.toLocaleLowerCase('en-US') === 'next' && attributes.href) {
      return attributes.href;
    }
  }
  return null;
}

function toGalleryPackage(entry) {
  const name = readElement(entry, 'Id');
  const version = readElement(entry, 'Version');
  if (!name || !version) return null;
  const published = readElement(entry, 'Published');
  const updated = readElement(entry, 'LastUpdated');
  return {
    name,
    version,
    title: readElement(entry, 'Title') || name,
    description: readElement(entry, 'Description') || readElement(entry, 'Summary'),
    authors: readElement(entry, 'Authors'),
    owners: readElement(entry, 'Owners'),
    tags: readElement(entry, 'Tags').split(/\s+/).filter(Boolean),
    projectUrl: readElement(entry, 'ProjectUrl'),
    publishedAt: published || null,
    updatedAt: updated || published || null,
    isLatest: readElement(entry, 'IsLatestVersion').toLocaleLowerCase('en-US') === 'true',
    isAbsoluteLatest: readElement(entry, 'IsAbsoluteLatestVersion').toLocaleLowerCase('en-US') === 'true',
    packageSize: Number(readElement(entry, 'PackageSize')) || null,
    packageHash: readElement(entry, 'PackageHash') || null,
    packageHashAlgorithm: readElement(entry, 'PackageHashAlgorithm') || null,
    dependencies: parseGalleryDependencies(readElement(entry, 'Dependencies')),
  };
}

export function parseGalleryDependencies(value) {
  const dependencies = [];
  for (const part of String(value || '').split('|')) {
    const match = part.trim().match(/^([^:]+):\s*(.*)$/);
    if (!match) continue;
    const name = match[1].trim();
    const versionRange = match[2].trim();
    if (!name) continue;
    dependencies.push({ name, versionRange: versionRange || '*' });
  }
  return dedupeDependencies(dependencies);
}

export function dedupeDependencies(items) {
  const byKey = new Map();
  for (const dependency of items || []) {
    const relation = dependency.relation || 'requires';
    const key = String(dependency.name).toLocaleLowerCase('en-US') + '\0'
      + String(dependency.versionRange || '*') + '\0' + relation;
    const existing = byKey.get(key);
    if (!existing) {
      const clone = { ...dependency };
      if (Array.isArray(dependency.declarationSources)) clone.declarationSources = [...new Set(dependency.declarationSources)];
      byKey.set(key, clone);
    } else {
      if (existing.declarationSources || dependency.declarationSources) {
        existing.declarationSources = [...new Set([
          ...(existing.declarationSources || []),
          ...(dependency.declarationSources || []),
        ])];
      }
      if (!existing.file && dependency.file) existing.file = dependency.file;
      if (!existing.line && dependency.line) existing.line = dependency.line;
    }
  }
  return [...byKey.values()];
}

export function parseGalleryFeed(xml) {
  if (typeof xml !== 'string' || xml.length > 25 * 1024 * 1024) {
    throw new Error('Gallery XML feed is missing or exceeds the 25 MiB limit.');
  }
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error('DTD and entity declarations are not accepted in Gallery XML.');
  const entries = [];
  const pattern = /<(?:[A-Za-z_][\w.-]*:)?entry\b[^>]*>([\s\S]*?)<\/(?:[A-Za-z_][\w.-]*:)?entry\s*>/gi;
  for (const match of xml.matchAll(pattern)) {
    const item = toGalleryPackage(match[1]);
    if (item) entries.push(item);
  }
  return { entries, nextLink: parseLinkHeader(xml) };
}

export function parseNuspec(xml) {
  if (typeof xml !== 'string' || xml.length > 2 * 1024 * 1024) throw new Error('Package nuspec is invalid or too large.');
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error('DTD and entity declarations are not accepted in package metadata.');
  const cleanXml = xml.replace(/<!--[\s\S]*?-->/g, '');
  const metadata = {};
  for (const field of ['id', 'version', 'title', 'authors', 'description', 'projectUrl', 'owners']) {
    metadata[field] = readElement(cleanXml, field);
  }
  const dependencies = [];
  const pattern = /<(?:[A-Za-z_][\w.-]*:)?dependency\b([^>]*?)(?:\/\s*>|>(?:[\s\S]*?)<\/(?:[A-Za-z_][\w.-]*:)?dependency\s*>)/gi;
  for (const match of cleanXml.matchAll(pattern)) {
    const attrs = parseAttributes(match[1]);
    if (attrs.id) dependencies.push({ name: attrs.id, versionRange: attrs.version || '*' });
  }
  return { metadata, dependencies: dedupeDependencies(dependencies) };
}
