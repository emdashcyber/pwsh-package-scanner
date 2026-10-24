import { getFreshnessState } from './freshness.js';

const $ = (selector) => document.querySelector(selector);
const base = $('meta[name="app-base"]')?.content || '/pwsh-package-scanner/';
const apiBase = new URL(base + 'api/v1/', window.location.origin);
const pageSize = 24;
const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
const state = { packages: [], filtered: [], page: 0, manifest: null };
const dateFormatter = new Intl.DateTimeFormat('en-AU', {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
  timeZone: 'UTC',
  timeZoneName: 'short',
});

const ui = {
  heading: $('#status-heading'),
  freshness: $('#freshness-pill'),
  statusCopy: $('#status-copy'),
  packages: $('#metric-packages'),
  latest: $('#metric-latest'),
  versions: $('#metric-versions'),
  incomplete: $('#metric-incomplete'),
  unscanned: $('#metric-unscanned'),
  updated: $('#updated-line'),
  search: $('#search'),
  finding: $('#finding-filter'),
  severity: $('#severity-filter'),
  assessment: $('#assessment-filter'),
  sort: $('#sort-order'),
  findingIds: $('#finding-ids'),
  count: $('#results-count'),
  message: $('#catalog-message'),
  list: $('#package-list'),
  pagination: $('#pagination'),
  pageLabel: $('#page-label'),
  previous: $('#previous-page'),
  next: $('#next-page'),
};

function fmtDate(value) {
  if (!value) return 'not available';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? 'not available' : dateFormatter.format(date);
}

function setMessage(title, body, kind = 'info') {
  ui.message.hidden = false;
  ui.message.dataset.kind = kind;
  ui.message.replaceChildren();
  const icon = document.createElement('span');
  icon.className = 'empty-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = kind === 'error' ? '!' : '◌';
  const heading = document.createElement('h3');
  heading.textContent = title;
  const paragraph = document.createElement('p');
  paragraph.textContent = body;
  ui.message.append(icon, heading, paragraph);
}

function updateFreshness(manifest) {
  const lastSuccess = manifest.lastSuccessfulScan;
  const freshness = getFreshnessState(manifest);
  const freshnessWindowHours = freshness.freshnessWindowHours;
  const stale = freshness.state === 'stale';
  const baselineInProgress = manifest.bootstrap && manifest.bootstrap.complete === false;
  ui.freshness.className = 'status-pill ' + (stale ? (lastSuccess ? 'status-stale' : 'status-unknown') : 'status-fresh');
  ui.freshness.textContent = baselineInProgress && lastSuccess && !stale
    ? 'Baseline in progress'
    : freshness.state === 'not_started' ? 'Not started' : stale ? 'Stale' : 'Recent scan';
  ui.heading.textContent = baselineInProgress
    ? 'Initial package baseline is in progress'
    : freshness.state === 'not_started' ? 'Initial scan has not been published' : stale ? 'Latest snapshot may be out of date' : 'Recent scan published';

  if (baselineInProgress) {
    const coverage = manifest.coverage || {};
    const scanned = Number(coverage.scannedLatestVersions || 0).toLocaleString('en-AU');
    ui.statusCopy.textContent = scanned + ' latest package versions have an assessment recorded so far. The initial catalog is being seeded in batches.'
      + (coverage.incompleteVersions ? ' Package-level coverage gaps are listed with each result.' : '');
  } else if (freshness.state === 'not_started') {
    ui.statusCopy.textContent = manifest.notice || 'The initial package catalog will appear after the first successful scan.';
  } else if (stale) {
    ui.statusCopy.textContent = 'No successful scan has arrived within the expected ' + freshnessWindowHours + '-hour window. Existing results remain available.';
  } else {
    ui.statusCopy.textContent = 'A successful scan completed within the last ' + freshnessWindowHours + ' hours. Package coverage gaps are reported separately.';
  }
  if (manifest.resultRefresh?.complete === false && !baselineInProgress) {
    const total = Number(manifest.resultRefresh.total || 0);
    const remaining = Number(manifest.lastBatch?.resultRefreshRemaining ?? total);
    if (total) ui.statusCopy.textContent += ' Earlier results are being refreshed: ' + Math.max(0, total - remaining).toLocaleString('en-AU') + ' of ' + total.toLocaleString('en-AU') + '.';
  }
  ui.updated.textContent = 'Last successful scan: ' + fmtDate(lastSuccess)
    + (manifest.lastAttemptAt ? ' · Last attempt: ' + fmtDate(manifest.lastAttemptAt) : '');

  const coverage = manifest.coverage || {};
  ui.packages.textContent = Number(coverage.listedPackages || 0).toLocaleString('en-AU');
  ui.latest.textContent = Number(coverage.scannedLatestVersions || 0).toLocaleString('en-AU');
  ui.versions.textContent = Number(coverage.scannedVersions || 0).toLocaleString('en-AU');
  ui.incomplete.textContent = Number(coverage.incompleteVersions || 0).toLocaleString('en-AU');
  ui.unscanned.textContent = Number(coverage.notScannedVersions || 0).toLocaleString('en-AU');
}

function normalizeAssessment(value) {
  return ['complete', 'incomplete', 'not_scanned'].includes(value) ? value : 'not_scanned';
}

function normalizeSeverity(value) {
  return severityOrder.includes(value) ? value : null;
}

function safeExternalUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

function packageSourceUrl(name, version) {
  return 'https://www.powershellgallery.com/packages/'
    + encodeURIComponent(name) + '/' + encodeURIComponent(version);
}

function makeBadge(text, className) {
  const badge = document.createElement('span');
  badge.className = className;
  badge.textContent = text;
  return badge;
}

function renderFinding(finding) {
  const item = document.createElement('li');
  item.className = 'finding-item severity-' + normalizeSeverity(finding.severity);
  const topline = document.createElement('div');
  topline.className = 'finding-topline';
  topline.append(
    makeBadge(finding.severity || 'unknown', 'finding-badge finding-' + normalizeSeverity(finding.severity)),
    makeBadge(finding.confidence || 'unknown confidence', 'assessment-badge'),
  );
  const heading = document.createElement('h4');
  heading.textContent = finding.title || finding.id || 'Scanner finding';
  item.append(topline, heading);

  if (finding.description) {
    const description = document.createElement('p');
    description.textContent = finding.description;
    item.append(description);
  }
  if (finding.evidence && (finding.evidence.file || finding.evidence.line || finding.evidence.snippet)) {
    const evidence = document.createElement('code');
    evidence.className = 'finding-evidence';
    const location = [finding.evidence.file, finding.evidence.line ? 'line ' + finding.evidence.line : null].filter(Boolean).join(':');
    evidence.textContent = (location ? location + '\n' : '') + (finding.evidence.snippet || '');
    item.append(evidence);
  }
  if (Array.isArray(finding.references) && finding.references.length) {
    const links = document.createElement('div');
    links.className = 'finding-links';
    for (const reference of finding.references.slice(0, 5)) {
      const href = safeExternalUrl(reference);
      if (!href) continue;
      const link = document.createElement('a');
      link.href = href;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      const hostname = new URL(href).hostname;
      link.textContent = hostname.includes('virustotal.com') ? 'VirusTotal hash search ↗'
        : hostname.includes('powershellgallery.com') ? 'PowerShell Gallery ↗'
          : 'Reference ↗';
      links.append(link);
    }
    if (links.childElementCount) item.append(links);
  }
  return item;
}

function renderDependencyGraph(entry, dependencies) {
  const section = document.createElement('section');
  section.className = 'dependency-graph';
  const heading = document.createElement('h4');
  heading.textContent = 'Dependency graph';
  const root = document.createElement('div');
  root.className = 'graph-root';
  const rootLabel = document.createElement('strong');
  rootLabel.textContent = 'Package';
  const rootName = document.createElement('span');
  rootName.textContent = entry.name;
  root.append(rootLabel, rootName);
  section.append(heading, root);

  if (!dependencies.length) {
    const empty = document.createElement('p');
    empty.className = 'details-empty';
    empty.textContent = 'No package or module dependency edges were declared or extracted for this version.';
    section.append(empty);
    return section;
  }

  const list = document.createElement('ul');
  list.className = 'graph-edge-list';
  for (const edge of dependencies) {
    const item = document.createElement('li');
    const status = ['resolved', 'bundled', 'package_not_found', 'no_matching_version', 'unsupported_range', 'gallery_unavailable', 'depth_limit', 'node_limit'].includes(edge.status)
      ? edge.status : 'unresolved';
    item.className = 'graph-edge graph-edge-' + status;
    const path = document.createElement('div');
    path.className = 'graph-edge-path';
    const parent = document.createElement('span');
    parent.className = 'graph-parent';
    parent.textContent = edge.parent || entry.name;
    const connector = document.createElement('span');
    connector.className = 'graph-connector';
    connector.textContent = edge.relation === 'contains' ? 'contains' : 'requires';
    const child = document.createElement('strong');
    child.textContent = edge.name + (edge.resolvedVersion ? '@' + edge.resolvedVersion : '');
    path.append(parent, connector, child);
    const meta = document.createElement('div');
    meta.className = 'graph-edge-meta';
    const badgeText = status === 'package_not_found' ? 'not found in Gallery'
      : status === 'no_matching_version' ? 'range not found in Gallery'
        : status.replaceAll('_', ' ');
    meta.append(makeBadge(badgeText, 'graph-status graph-status-' + status));
    const range = document.createElement('span');
    range.textContent = 'declared range ' + (edge.versionRange || '*');
    meta.append(range);
    if (Array.isArray(edge.declarationSources) && edge.declarationSources.length) {
      const source = document.createElement('span');
      source.textContent = 'from ' + edge.declarationSources.join(', ');
      meta.append(source);
    }
    if (edge.file) {
      const evidence = document.createElement('code');
      evidence.textContent = edge.file + (edge.line ? ':' + edge.line : '');
      meta.append(evidence);
    }
    item.append(path, meta);
    list.append(item);
  }
  section.append(list);
  return section;
}

function renderBinaryArtifacts(artifacts, result = {}) {
  const inventory = Array.isArray(result.fileInventory) ? result.fileInventory : [];
  const binaryFiles = inventory.filter((file) => /\.(?:dll|exe|msi|com|sys|bin|scr|so|dylib)$/i.test(file.path || ''));
  if (!artifacts.length && !binaryFiles.length) return null;
  const section = document.createElement('section');
  section.className = 'binary-artifacts';
  const heading = document.createElement('h4');
  heading.textContent = 'Binary files';
  const note = document.createElement('p');
  note.className = 'details-empty';
  note.textContent = artifacts.length
    ? 'Each listed binary was hashed and checked with ClamAV. VirusTotal links open a hash search; files are not uploaded.'
    : 'Binary checks are pending the resumable results refresh. These files have not yet been hashed or scanned with ClamAV.';
  const list = document.createElement('ul');
  list.className = 'binary-artifact-list';
  for (const artifact of artifacts.length ? artifacts : binaryFiles) {
    const item = document.createElement('li');
    const path = document.createElement('strong');
    path.textContent = artifact.path || 'Binary file';
    if (!artifacts.length) {
      const pending = document.createElement('span');
      pending.textContent = 'Pending hash and ClamAV check';
      item.append(path, pending);
      list.append(item);
      continue;
    }
    const hash = document.createElement('code');
    hash.textContent = 'SHA-256 ' + (artifact.sha256 || 'unavailable');
    const status = artifact.clamav?.status || 'error';
    item.append(path, hash, makeBadge('ClamAV ' + status, 'assessment-badge ' + (status === 'clean' ? 'assessment-complete' : status === 'match' ? 'finding-badge finding-high' : 'assessment-incomplete')));
    if (artifact.virusTotalSearchUrl) {
      const href = safeExternalUrl(artifact.virusTotalSearchUrl);
      if (href) {
        const link = document.createElement('a');
        link.href = href;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = 'Search hash on VirusTotal ↗';
        item.append(link);
      }
    }
    const tool = artifact.clamav || {};
    if (tool.engineVersion || tool.databaseVersion) {
      const version = document.createElement('small');
      version.textContent = 'ClamAV ' + (tool.engineVersion || 'unknown engine')
        + (tool.databaseVersion ? ' · signature database ' + tool.databaseVersion : '')
        + (tool.databaseDate ? ' · ' + tool.databaseDate : '');
      item.append(version);
    }
    list.append(item);
  }
  section.append(heading, note, list);
  return section;
}

async function loadDetails(entry, detailNode, selectedVersion = entry.latestVersion) {
  detailNode.replaceChildren();
  const loading = document.createElement('p');
  loading.className = 'details-loading';
  loading.textContent = 'Loading version findings…';
  detailNode.append(loading);
  try {
    const versionRecord = (entry.versions || []).find((item) => item.version === selectedVersion);
    let result;
    if (normalizeAssessment(versionRecord?.assessment) === 'not_scanned') {
      result = { assessment: 'not_scanned', dependencies: [], findings: [] };
    } else {
      const path = versionRecord?.resultPath || (selectedVersion === entry.latestVersion ? entry.latestResultPath : null);
      if (!path) throw new Error('No result document is available for this version.');
      const response = await fetch(new URL(path, apiBase), { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error('The result document could not be loaded (' + response.status + ').');
      result = await response.json();
    }
    detailNode.replaceChildren();
    const source = document.createElement('a');
    source.className = 'package-source';
    source.href = packageSourceUrl(entry.name, selectedVersion);
    source.target = '_blank';
    source.rel = 'noopener noreferrer';
    source.textContent = 'View package on PowerShell Gallery ↗';
    const versionLabel = document.createElement('label');
    versionLabel.className = 'version-picker';
    const versionCaption = document.createElement('span');
    versionCaption.textContent = 'Version result';
    const versionSelect = document.createElement('select');
    versionSelect.setAttribute('aria-label', 'Choose a version result for ' + entry.name);
    for (const version of entry.versions || []) {
      const option = document.createElement('option');
      option.value = version.version;
      option.textContent = version.version + ' · ' + normalizeAssessment(version.assessment).replace('_', ' ');
      option.selected = version.version === selectedVersion;
      versionSelect.append(option);
    }
    versionSelect.addEventListener('change', () => loadDetails(entry, detailNode, versionSelect.value));
    versionLabel.append(versionCaption, versionSelect);
    detailNode.append(source, versionLabel);

    const scanDate = document.createElement('p');
    scanDate.className = 'details-empty';
    scanDate.textContent = 'Last scanned: ' + fmtDate(result.scannedAt || versionRecord?.scannedAt);
    detailNode.append(scanDate);

    if (entry.versionInventoryComplete === false && entry.versionInventoryNote) {
      const note = document.createElement('p');
      note.className = 'details-empty';
      note.textContent = entry.versionInventoryNote;
      detailNode.append(note);
    }

    const dependencies = Array.isArray(result.dependencies) ? result.dependencies : [];
    detailNode.append(renderDependencyGraph(entry, dependencies));
    const binarySection = renderBinaryArtifacts(Array.isArray(result.binaryArtifacts) ? result.binaryArtifacts : [], result);
    if (binarySection) detailNode.append(binarySection);

    const findings = Array.isArray(result.findings) ? result.findings : [];
    if (!findings.length) {
      const empty = document.createElement('p');
      empty.className = 'details-empty';
      empty.textContent = result.assessment === 'complete'
        ? 'No findings detected by the enabled checks for this version. This is not a guarantee of safety.'
        : result.assessment === 'not_scanned'
          ? 'This version is known to the Gallery but has not been scanned.'
          : 'No findings are published for this version because the assessment is incomplete.';
      detailNode.append(empty);
    } else {
      const list = document.createElement('ul');
      list.className = 'finding-list';
      for (const finding of findings) list.append(renderFinding(finding));
      detailNode.append(list);
    }
  } catch (error) {
    detailNode.replaceChildren();
    const message = document.createElement('p');
    message.className = 'details-empty';
    message.textContent = error.message;
    detailNode.append(message);
  }
}

function renderPackage(entry) {
  const card = document.createElement('article');
  card.className = 'package-card';
  const summary = document.createElement('div');
  summary.className = 'package-summary';
  summary.setAttribute('role', 'group');
  const titleWrap = document.createElement('div');
  titleWrap.className = 'package-heading';
  const title = document.createElement('h3');
  title.className = 'package-name';
  const link = document.createElement('a');
  link.href = packageSourceUrl(entry.name, entry.latestVersion || '');
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  link.textContent = entry.name;
  title.append(link);
  const version = document.createElement('span');
  version.className = 'package-version';
  version.textContent = 'v' + (entry.latestVersion || 'unknown');
  titleWrap.append(title, version);

  const description = document.createElement('p');
  description.className = 'package-description';
  description.textContent = entry.description || 'No package description is available.';
  const meta = document.createElement('div');
  meta.className = 'package-meta';
  const assessment = normalizeAssessment(entry.latestAssessment);
  meta.append(makeBadge(assessment.replace('_', ' '), 'assessment-badge assessment-' + assessment));
  if (entry.versionInventoryComplete === false) meta.append(makeBadge('version history partial', 'assessment-badge assessment-incomplete'));
  const severity = normalizeSeverity(entry.highestSeverity);
  if (Number(entry.latestFindingCount || 0) > 0 && severity) {
    meta.append(makeBadge(
      Number(entry.latestFindingCount).toLocaleString('en-AU') + ' finding' + (Number(entry.latestFindingCount) === 1 ? '' : 's'),
      'finding-badge finding-' + severity,
    ));
  } else if (assessment === 'complete') {
    meta.append(makeBadge('no findings', 'finding-badge'));
  }

  const scannedAt = document.createElement('p');
  scannedAt.className = 'package-scan-date';
  scannedAt.textContent = 'Latest scan: ' + fmtDate(entry.latestScannedAt);
  const matched = document.createElement('p');
  matched.className = 'package-matching-versions';
  if (entry.matchingVersions?.length) {
    const visible = entry.matchingVersions.slice(0, 8).map((item) => item.version);
    matched.textContent = 'Matching versions: ' + visible.join(', ')
      + (entry.matchingVersions.length > visible.length ? ' +' + (entry.matchingVersions.length - visible.length) + ' more' : '');
  }

  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'package-toggle';
  toggle.setAttribute('aria-label', 'Show scan details for ' + entry.name);
  toggle.setAttribute('aria-expanded', 'false');
  toggle.textContent = '⌄';
  const details = document.createElement('div');
  details.className = 'package-details';
  details.hidden = true;
  toggle.addEventListener('click', () => {
    const open = toggle.getAttribute('aria-expanded') === 'true';
    toggle.setAttribute('aria-expanded', String(!open));
    details.hidden = open;
    if (!open && !details.dataset.loaded) {
      details.dataset.loaded = 'true';
      loadDetails(entry, details, entry.matchingVersions?.[0]?.version || entry.latestVersion);
    }
  });
  summary.append(titleWrap, meta, description, scannedAt);
  if (matched.textContent) summary.append(matched);
  summary.append(toggle);
  card.append(summary, details);
  return card;
}

function applyFilters() {
  const q = ui.search.value.trim().toLocaleLowerCase('en-AU');
  const findingId = ui.finding.value.trim().toLocaleLowerCase('en-AU');
  const severity = ui.severity.value;
  const assessment = ui.assessment.value;
  const matched = state.packages.flatMap((entry) => {
    const matchesName = !q || (entry.name + ' ' + (entry.description || '')).toLocaleLowerCase('en-AU').includes(q);
    const matchesAssessment = assessment === 'all' || normalizeAssessment(entry.latestAssessment) === assessment;
    const matchesSeverity = severity === 'all'
      || (severity === 'none' ? Number(entry.latestFindingCount || 0) === 0 && normalizeAssessment(entry.latestAssessment) === 'complete'
        : normalizeSeverity(entry.highestSeverity) === severity);
    const matchingVersions = findingId
      ? (entry.versions || []).filter((version) => (version.findingIds || []).some((id) => String(id).toLocaleLowerCase('en-AU') === findingId))
        .sort((a, b) => Date.parse(b.scannedAt || '') - Date.parse(a.scannedAt || ''))
      : [];
    const matchesFinding = !findingId || matchingVersions.length > 0;
    return matchesName && matchesAssessment && matchesSeverity && matchesFinding
      ? [{ ...entry, matchingVersions }]
      : [];
  });
  const sort = ui.sort.value;
  if (sort === 'name') matched.sort((a, b) => String(a.name).localeCompare(String(b.name), 'en', { sensitivity: 'base' }));
  else if (sort === 'findings') matched.sort((a, b) => {
    const count = Number(b.totalFindingCount || (b.versions || []).reduce((sum, item) => sum + Number(item.findingCount || 0), 0))
      - Number(a.totalFindingCount || (a.versions || []).reduce((sum, item) => sum + Number(item.findingCount || 0), 0));
    return count || String(a.name).localeCompare(String(b.name), 'en', { sensitivity: 'base' });
  });
  else matched.sort((a, b) => (Date.parse(b.latestScannedAt || '') || 0) - (Date.parse(a.latestScannedAt || '') || 0)
    || String(a.name).localeCompare(String(b.name), 'en', { sensitivity: 'base' }));
  state.filtered = matched;
  state.page = 0;
  renderPage();
}

function renderPage() {
  ui.list.replaceChildren();
  const start = state.page * pageSize;
  const rows = state.filtered.slice(start, start + pageSize);
  for (const entry of rows) ui.list.append(renderPackage(entry));
  const totalPages = Math.max(1, Math.ceil(state.filtered.length / pageSize));
  ui.count.textContent = state.filtered.length.toLocaleString('en-AU') + ' package' + (state.filtered.length === 1 ? '' : 's');
  ui.pagination.hidden = state.filtered.length <= pageSize;
  ui.pageLabel.textContent = 'Page ' + (state.page + 1) + ' of ' + totalPages;
  ui.previous.disabled = state.page === 0;
  ui.next.disabled = state.page >= totalPages - 1;
  if (state.filtered.length) {
    ui.message.hidden = true;
  } else if (state.packages.length) {
    setMessage('No packages match these filters', 'Try a different search or clear one of the filters.');
  } else {
    ui.message.hidden = false;
  }
}

async function loadCatalog() {
  const manifestResponse = await fetch(new URL('manifest.json', apiBase), { headers: { Accept: 'application/json' } });
  if (!manifestResponse.ok) throw new Error('The scanner manifest could not be loaded (' + manifestResponse.status + ').');
  const manifest = await manifestResponse.json();
  state.manifest = manifest;
  updateFreshness(manifest);

  if (!Array.isArray(manifest.shards) || manifest.shards.length === 0) {
    setMessage('Initial catalog has not been published', manifest.notice || 'The first catalog scan has not completed yet.');
    ui.count.textContent = '0 packages';
    return;
  }
  const chunks = await Promise.all(manifest.shards.map(async (path) => {
    const response = await fetch(new URL(path, apiBase), { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error('A catalog shard could not be loaded (' + response.status + ').');
    const shard = await response.json();
    return Array.isArray(shard.packages) ? shard.packages : [];
  }));
  state.packages = chunks.flat();
  const ids = [...new Set(state.packages.flatMap((entry) => (entry.versions || []).flatMap((version) => version.findingIds || [])))].sort();
  ui.findingIds.replaceChildren();
  for (const id of ids) {
    const option = document.createElement('option');
    option.value = id;
    ui.findingIds.append(option);
  }
  applyFilters();
}

ui.search.addEventListener('input', applyFilters);
ui.finding.addEventListener('input', applyFilters);
ui.severity.addEventListener('change', applyFilters);
ui.assessment.addEventListener('change', applyFilters);
ui.sort.addEventListener('change', applyFilters);
ui.previous.addEventListener('click', () => { state.page = Math.max(0, state.page - 1); renderPage(); });
ui.next.addEventListener('click', () => {
  const totalPages = Math.max(1, Math.ceil(state.filtered.length / pageSize));
  state.page = Math.min(totalPages - 1, state.page + 1);
  renderPage();
});

loadCatalog().catch((error) => {
  ui.heading.textContent = 'Published catalog unavailable';
  ui.freshness.className = 'status-pill status-unknown';
  ui.freshness.textContent = 'Unavailable';
  ui.statusCopy.textContent = 'The existing site remains available, but scan data could not be loaded right now.';
  ui.count.textContent = 'Catalog failed to load';
  setMessage('Could not load the catalog', error.message, 'error');
});
