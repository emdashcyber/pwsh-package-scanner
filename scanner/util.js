import { createHash } from 'node:crypto';

export function sha256(input) {
  return createHash('sha256').update(input).digest('hex');
}

export function normalizePackageName(value) {
  return String(value || '').trim().toLocaleLowerCase('en-US');
}

export function packageKey(value) {
  return Buffer.from(normalizePackageName(value), 'utf8').toString('base64url');
}

export function versionKey(value) {
  return Buffer.from(String(value || ''), 'utf8').toString('base64url');
}

export function parseBoolean(value) {
  return String(value || '').toLocaleLowerCase('en-US') === 'true';
}

export function safeString(value, maxLength = 4000) {
  return String(value ?? '').replace(/\u0000/g, '').slice(0, maxLength);
}

export function nowIso() {
  return new Date().toISOString();
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function mapLimit(items, concurrency, worker) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const count = Math.min(Math.max(1, concurrency), items.length);
  await Promise.all(Array.from({ length: count }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex++;
      results[index] = await worker(items[index], index);
    }
  }));
  return results;
}

export function compareText(a, b) {
  return String(a).localeCompare(String(b), 'en', { sensitivity: 'base' });
}

export function xmlEscapeLiteral(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&apos;');
}

export function jsonClone(value) {
  return JSON.parse(JSON.stringify(value));
}
