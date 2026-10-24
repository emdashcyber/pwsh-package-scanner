# PowerShell Gallery Security Research Scanner

A free, open research project that continuously reviews publicly listed PowerShell Gallery modules, scripts, and DSC resources. It publishes a searchable dashboard and read-only static JSON API at:

**https://emdashcyber.com/pwsh-package-scanner/**

Automated findings are evidence-backed research signals. A complete scan with no results is **not** a statement that a package is safe, and the service does not automatically label packages malicious. Definitive claims require human review.

## What it does

- Scans the latest version of each listed package for the initial baseline, then observes new and updated versions. Pre-launch versions other than the latest remain explicitly unscanned.
- Polls the PowerShell Gallery hourly on a best-effort basis, using an overlapping update window, deduplication, and rolling metadata reconciliation.
- Inspects `.nupkg` metadata, package manifests, dependency declarations, archive inventory, version-to-version metadata and file changes, and PowerShell syntax trees. It combines pinned PSScriptAnalyzer checks with project-maintained static rules.
- Reads `RequiredModules` and `ModuleList` from `.psd1` files and `#Requires -Modules` from scripts. `ModuleList` is represented as a contains edge; required declarations are checked against Gallery package and version listings.
- Hashes supported binary files, scans them with ClamAV using refreshed signatures, and publishes VirusTotal hash-search links. Files are never uploaded to VirusTotal.
- Resolves bounded dependency graphs and queries OSV for supported NuGet package identities. Curated PowerShell Gallery advisories live in `advisories/powershell-gallery.json`.
- Publishes `complete`, `incomplete`, and `not_scanned` states, coverage counts, timestamps, findings, redacted evidence, references, and package SHA-256 hashes.

The scanner never installs, imports, or executes Gallery package content. ZIP entries are analyzed in memory with limits on archive size, entry count, expanded size, per-file size, and compression ratio. PowerShell static analysis and binary checks run in temporary directories with a restricted environment. Unrecognized dependency identities, unsupported ranges, failed binary scans, and upstream failures are reflected as coverage gaps.

## Repository layout

- `scanner/`, `scripts/`, and the root `tests/` contain the scanner, data pipeline, and scanner tests.
- `site/` contains the Astro dashboard, static API, site-specific tests, dependencies, and build output.
- `advisories/` contains the curated Gallery advisory data.

## Static API

The API is versioned under `/pwsh-package-scanner/api/v1/`:

- `manifest.json` reports schema version, status, timestamps, coverage, and catalog shard locations.
- `shards/{shard}.json` contains searchable package summaries and known versions. Shard keys are two-digit lowercase hexadecimal values.
- `packages/{packageKey}/{versionKey}.json` contains one version's scan result. Package IDs are lowercased and Base64url-encoded; version strings are Base64url-encoded.
- `openapi.json` describes the public API.

Known pre-launch versions are listed as `not_scanned` in the catalog with known publish/update dates; they do not have separate result documents. This keeps scan results focused on versions that were actually analyzed.

The manifest also references `state/{shard}.json` persistence shards. These are publicly readable because GitHub Pages is static; the scanner loads them to merge new findings with the last published snapshot. Treat these as implementation data, not a stable consumer API.

The dashboard supports package search, finding-ID filters across scanned versions, assessment/severity filters, and sorting by latest scan time, name, or total findings. It displays per-version dependency graphs, scan dates, binary hashes, ClamAV results, and VirusTotal hash-search links. A complete version with an empty findings list displays “No findings detected.” Incomplete and unscanned versions are shown separately.

## Local use

Requirements: Node.js 26, PowerShell 7.6.8, and PSScriptAnalyzer 1.25.0 for complete PowerShell analysis. Install ClamAV and refresh its signatures for complete binary coverage.

Install site dependencies and run the dashboard:

```sh
cd site
npm ci
npm run dev
```

To seed the initial baseline locally, run this from the repository root:

```sh
npm run scan:bootstrap:local
```

The command reads and resumes the snapshot under `site/public/api/v1/`, processes 200 latest packages per batch by default, and writes a new snapshot after each batch until the Gallery baseline is complete. It then runs one incremental and reconciliation pass to catch changes published during the baseline. If interrupted or a Gallery feed fails, run it again to resume. A feed failure exits non-zero after saving the last completed batch. Set `BOOTSTRAP_BATCH_SIZE` or `SCAN_CONCURRENCY` to tune the batch size or concurrency. Set `PSSCRIPTANALYZER_MODULE_PATH` to the directory containing the pinned PSScriptAnalyzer module if it is not in the default PowerShell module path.

The local snapshot in Git is the scanner's state source of truth. Each workflow run merges with that checked-in snapshot, writes scan results under `site/public/api/v1/`, validates and commits only changed API data, then builds and deploys the same snapshot. Set `PSGALLERY_API_ROOT` to use a compatible test Gallery endpoint. Set `PSSCRIPTANALYZER_ENABLED=false` only for local experiments; those results do not include the pinned analyzer checks. Set `CLAMAV_SCAN_COMMAND` to `clamscan` or `clamdscan` and `CLAMAV_DATABASE_VERSION`/`CLAMAV_DATABASE_DATE` to report local signature metadata.

Build and preview the static site from `site/`:

```sh
npm run build
npm run preview
```

From the repository root, `npm test` runs scanner fixtures, `npm --prefix site test` runs API contract fixtures, and `npm run check` runs both suites, builds the Astro site, and verifies the generated base paths and API documents.

## GitHub Actions and deployment

`.github/workflows/research-scan.yml` runs on code pushes to `main`, hourly at minute 17 UTC, and daily at 23:43 UTC. The daily run refreshes OSV matches; maintainers can request that refresh during a manual run. The read-only scan job installs pinned PowerShell 7.6.8 and PSScriptAnalyzer 1.25.0 plus ClamAV with refreshed signatures. A separate job validates and commits changed API data with `contents: write`; the final job builds the committed snapshot from `site/` and deploys `site/dist`. Data-only commits do not retrigger scans. `.github/workflows/validate.yml` runs the offline checks for pull requests.

GitHub Actions schedules are best-effort. The dashboard marks the service stale after six hours without a successful scan and displays the last attempt, last successful scan, package coverage, and any in-progress refresh of older scanned versions. Package-level incomplete checks do not degrade the Gallery service status. A failed workflow leaves the previously deployed Pages site available.

To publish, create or use the public repository `emdashcyber/pwsh-package-scanner`, set **Settings → Pages → Build and deployment → Source** to **GitHub Actions**, and push this project to its `main` branch. The project site uses `/pwsh-package-scanner/` as its Astro base path and the EmDash Cyber custom domain.

## Contributing rules and advisory curation

Security rules should include positive and negative fixtures, stable rule IDs, severity and confidence rationale, and a reference where possible. Curated advisories should include a stable ID, package name, affected NuGet version range, source, references, and a short description. Keep curated records evidence-backed and avoid publishing definitive malicious-package claims without human review.

Please report false positives, false negatives, or coverage gaps through the project issue tracker. Include the package ID, version, finding ID (if applicable), and supporting context.

## License

MIT. See [LICENSE](LICENSE).
