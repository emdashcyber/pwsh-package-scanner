export function getFreshnessState(manifest = {}, now = Date.now()) {
  const freshnessWindowHours = Number(manifest.freshnessWindowHours) || 6;
  const scanTime = Date.parse(manifest.lastSuccessfulScan || '');
  if (!Number.isFinite(scanTime)) return { state: 'not_started', freshnessWindowHours };
  const stale = now - scanTime > freshnessWindowHours * 60 * 60 * 1000;
  return { state: stale ? 'stale' : 'recent', freshnessWindowHours };
}
