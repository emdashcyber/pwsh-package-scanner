import { parseGalleryFeed } from './xml.js';
import { sleep } from './util.js';
import { resolveDependencyGraph } from './dependencies.js';

const DEFAULT_API_ROOT = 'https://www.powershellgallery.com/api/v2';
const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_PACKAGE_TIMEOUT_MS = 120_000;
const MAX_PACKAGE_BYTES = 100 * 1024 * 1024;
const MAX_FEED_BYTES = 25 * 1024 * 1024;
const BYTES_PER_MIB = 1024 * 1024;

function quoteOData(value) {
  return "'" + String(value).replaceAll("'", "''") + "'";
}

function assertGalleryUrl(value, allowedOrigin) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== allowedOrigin || !url.pathname.startsWith('/api/v2/')) {
    throw new Error('Gallery pagination returned a URL outside the expected HTTPS API origin.');
  }
  return url;
}

async function readLimitedBody(response, maxBytes) {
  if (!response.body) throw new Error('Gallery response had no body.');
  const sizeLimit = Number.isInteger(maxBytes / BYTES_PER_MIB)
    ? (maxBytes / BYTES_PER_MIB) + ' MiB'
    : maxBytes + ' bytes';
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new Error('Gallery response exceeds its ' + sizeLimit + ' size limit.');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error('Gallery response exceeds its ' + sizeLimit + ' size limit.');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

export class GalleryClient {
  constructor({
    apiRoot = process.env.PSGALLERY_API_ROOT || DEFAULT_API_ROOT,
    fetcher = globalThis.fetch,
    retryCount = 3,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    packageTimeoutMs = DEFAULT_PACKAGE_TIMEOUT_MS,
    wait = sleep,
    versionCacheLimit = 32,
  } = {}) {
    this.apiRoot = apiRoot.replace(/\/+$/, '');
    this.packageRoot = new URL('/api/v2/package/', this.apiRoot).href;
    this.origin = new URL(this.apiRoot).origin;
    this.fetcher = fetcher;
    this.retryCount = retryCount;
    this.timeoutMs = timeoutMs;
    this.packageTimeoutMs = packageTimeoutMs;
    this.wait = wait;
    this.versionCacheLimit = Math.max(1, Math.floor(Number(versionCacheLimit) || 32));
    this.versionCache = new Map();
  }

  cacheVersionList(key, value) {
    this.versionCache.delete(key);
    this.versionCache.set(key, value);
    while (this.versionCache.size > this.versionCacheLimit) {
      this.versionCache.delete(this.versionCache.keys().next().value);
    }
  }

  clearVersionCache() {
    this.versionCache.clear();
  }

  async request(url, {
    maxBytes = MAX_FEED_BYTES,
    method = 'GET',
    body,
    headers = {},
    timeoutMs = this.timeoutMs,
  } = {}) {
    let lastError;
    for (let attempt = 0; attempt <= this.retryCount; attempt++) {
      try {
        const response = await this.fetcher(url, {
          method,
          body,
          headers: {
            Accept: 'application/atom+xml, application/xml;q=0.9, */*;q=0.5',
            'User-Agent': 'EmDashCyber-PowerShell-Gallery-Scanner/0.1',
            ...headers,
          },
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (response.status === 429 || response.status >= 500) {
          const retryAfter = Number(response.headers.get('retry-after'));
          if (attempt < this.retryCount) {
            await this.wait(Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 30_000) : 500 * (2 ** attempt));
            continue;
          }
        }
        if (!response.ok) {
          const error = new Error('Gallery returned HTTP ' + response.status + '.');
          error.status = response.status;
          throw error;
        }
        return await readLimitedBody(response, maxBytes);
      } catch (error) {
        lastError = error;
        if (error?.status >= 400 && error?.status < 500 && error.status !== 429) break;
        if (attempt >= this.retryCount) break;
        await this.wait(500 * (2 ** attempt));
      }
    }
    throw lastError || new Error('Gallery request failed.');
  }

  async readFeedPage(url) {
    const safeUrl = assertGalleryUrl(url, this.origin);
    const body = await this.request(safeUrl.href);
    return parseGalleryFeed(body.toString('utf8'));
  }

  async fetchPages(firstUrl, maxEntries = Infinity) {
    const entries = [];
    const seenPageUrls = new Set();
    let url = firstUrl;
    while (url && entries.length < maxEntries) {
      const safeUrl = assertGalleryUrl(url, this.origin);
      if (seenPageUrls.has(safeUrl.href)) throw new Error('Gallery feed pagination loop detected.');
      seenPageUrls.add(safeUrl.href);
      const page = await this.readFeedPage(safeUrl.href);
      entries.push(...page.entries.slice(0, Math.max(0, maxEntries - entries.length)));
      url = page.nextLink ? new URL(page.nextLink, safeUrl).href : null;
    }
    return entries;
  }

  async listLatestAfter(lastId = '', limit = 200) {
    const filterParts = ['IsAbsoluteLatestVersion eq true'];
    if (lastId) filterParts.push('Id gt ' + quoteOData(lastId));
    const url = new URL(this.apiRoot + '/Packages');
    url.searchParams.set('$filter', filterParts.join(' and '));
    url.searchParams.set('$orderby', 'Id asc');
    url.searchParams.set('$top', String(Math.min(Math.max(1, limit), 1000)));
    return this.fetchPages(url.href, limit);
  }

  async listUpdatedSince(timestamp, limit = 5000) {
    const time = new Date(timestamp);
    if (!Number.isFinite(time.valueOf())) throw new Error('Invalid Gallery update cursor.');
    const stamp = time.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const url = new URL(this.apiRoot + '/Packages');
    url.searchParams.set('$filter', "LastUpdated ge datetime'" + stamp + "'");
    url.searchParams.set('$orderby', 'LastUpdated asc');
    url.searchParams.set('$top', '1000');
    return this.fetchPages(url.href, limit);
  }

  async listPackageVersions(name) {
    const key = String(name).toLocaleLowerCase('en-US');
    if (this.versionCache.has(key)) return this.versionCache.get(key);
    const url = new URL(this.apiRoot + '/FindPackagesById()');
    url.searchParams.set('id', "'" + String(name).replaceAll("'", "''") + "'");
    const promise = this.fetchPages(url.href, 1000);
    this.cacheVersionList(key, promise);
    try {
      const versions = await promise;
      this.cacheVersionList(key, versions);
      return versions;
    } catch (error) {
      this.versionCache.delete(key);
      throw error;
    }
  }

  async getPackageVersion(name, version) {
    const url = new URL(this.apiRoot + '/Packages');
    url.searchParams.set('$filter', 'Id eq ' + quoteOData(name) + ' and Version eq ' + quoteOData(version));
    url.searchParams.set('$top', '1');
    const entries = await this.fetchPages(url.href, 1);
    return entries.find((item) => item.name.toLocaleLowerCase('en-US') === String(name).toLocaleLowerCase('en-US')
      && item.version === String(version)) || null;
  }

  resolveDependencyGraph(dependencies, options) {
    return resolveDependencyGraph(dependencies, this, options);
  }

  packageUrl(name, version) {
    return this.packageRoot + encodeURIComponent(name) + '/' + encodeURIComponent(version);
  }

  async downloadPackage(name, version, maxBytes = MAX_PACKAGE_BYTES) {
    return this.request(this.packageUrl(name, version), {
      maxBytes,
      timeoutMs: this.packageTimeoutMs,
      headers: { Accept: 'application/octet-stream, application/zip;q=0.9, */*;q=0.5' },
    });
  }
}

export function galleryApiRoot() {
  return process.env.PSGALLERY_API_ROOT || DEFAULT_API_ROOT;
}
