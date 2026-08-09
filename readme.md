***Vulnerability Database Downloaders***

Tools to download vulnerability data for use with Dependency-Track's offline mirroring, in the
same JSON/ZIP shapes DT already knows how to read.

- `osv_database_downloader.py` -- OSV (Open Source Vulnerabilities), per-ecosystem
- `nvd_database_downloader.py` -- NIST NVD, full catalog or recent changes
- `cert_fr_fetch.py` -- CERT-FR (French CERT) advisories and alerts

## Enterprise Proxy

All three tools work identically behind a corporate proxy, and require no configuration at all
when there isn't one. Outbound requests go through an explicit proxy override resolved in this
order:

1. `--proxy` CLI flag
2. `proxy` in `./config.json` (copy `config.json.example` and fill in your proxy URL;
   `config.json` is gitignored)
3. Neither set: the standard `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` environment variables are
   still honored automatically (the underlying `requests` library reads them on its own)

```bash
python osv_database_downloader.py --proxy http://user:pass@proxy.company.com:8080
python nvd_database_downloader.py --mode full --source zip --proxy http://proxy.company.com:8080
python cert_fr_fetch.py --proxy http://user:pass@proxy.company.com:8080
```

---

# OSV Database Downloader

A tool to download OSV (Open Source Vulnerabilities) ecosystem data with incremental update support.

## Features

- Downloads complete OSV database for all ecosystems
- Supports incremental updates using `modified_id.csv` files
- Downloads both global and per-ecosystem modified ID files
- Automatic directory creation for organized file storage

## Usage

### Basic Usage (Incremental Mode)
```bash
python osv_database_downloader.py
```

### Force Full Download
```bash
python osv_database_downloader.py --force-full
```

### Debug Mode
```bash
python osv_database_downloader.py --debug
```

### Command Line Options

- `--force-full`: Force download of complete database (ignores timestamps)
- `--incremental`: Perform incremental update only (default behavior)
- `--debug`: Enable debug logging for troubleshooting
- `--proxy`: Proxy URL for all outbound requests (see [Enterprise Proxy](#enterprise-proxy))

## Output Structure

The script creates a `./download/osv/` directory with the following structure:

```
download/osv/
├── osv_ecosystems.txt          # List of all available ecosystems
├── global_modified_id.csv      # Global list of modified vulnerabilities
├── timestamps.json             # Per-ecosystem incremental state
├── PyPI.zip                    # PyPI advisories: full DB on first run, changed-only afterwards
├── npm.zip                     # npm advisories: full DB on first run, changed-only afterwards
├── ...                         # Other ecosystem ZIP files
├── PyPI/                       # Per-ecosystem directories
│   └── modified_id.csv         # PyPI-specific modified vulnerabilities
├── npm/
│   └── modified_id.csv         # npm-specific modified vulnerabilities
└── ...
```

`{ecosystem}.zip` is always named exactly that (never a dated/versioned filename) --
Dependency-Track's offline OSV reader looks for that fixed name and deletes it once it has
successfully mirrored its contents, so the script naturally regenerates it fresh each run.

## Incremental Updates & Timestamp Tracking

Incremental state is tracked **per ecosystem** (in `./download/osv/timestamps.json`), not with a
single global flag -- so adding a new ecosystem to track later gets its own full download,
while already-tracked ecosystems keep receiving true incremental updates.

### Download Behavior

**First run for an ecosystem (or `--force-full`):**
- Downloads the complete `all.zip` for that ecosystem
- Records the run's start time as that ecosystem's watermark

**Subsequent runs (incremental, default):**
- Downloads that ecosystem's `modified_id.csv` and compares each entry's timestamp against the
  ecosystem's stored watermark
- Individually downloads every advisory changed since the watermark and packages them into
  `{ecosystem}.zip` (same file DT reads either way -- it does not care whether the zip holds a
  full or partial advisory set)
- If more than 250 advisories changed, falls back to a full `all.zip` download instead (matching
  the threshold Dependency-Track itself uses for incremental mirroring) -- fetching 250+
  individual files is more expensive than one archive
- If nothing changed, no zip is (re)written, but the watermark still advances

### modified_id.csv Files

The script downloads two types of change tracking files:

1. **Global modified_id.csv**: Downloaded for reference; not currently used to decide what to download
2. **Per-ecosystem modified_id.csv**: Compared against that ecosystem's stored watermark to determine exactly which advisories changed since the last successful run

---

# NVD Database Downloader

Downloads NVD CVE data, always in the same JSON shape as the NVD API 2.0 response
(`resultsPerPage`/`startIndex`/`totalResults`/`format`/`version`/`timestamp`/`vulnerabilities[].cve`)
-- the same shape Dependency-Track's offline NVD import expects.

## Modes

| Mode | Source | What it does |
|------|--------|---------------|
| `--mode full --source zip` (recommended for a first bootstrap) | Official yearly `nvdcve-2.0-<year>.json.zip` feeds | Fastest full-history download. Extracted directly under NVD's own per-year filenames (`nvdcve-2.0-<year>.json`) so DT's offline mode reads them natively, no renaming or merging. Uses each feed's `.meta` file to skip years unchanged since the last run (or `--force-full` to re-download everything). |
| `--mode full --source api` | NVD API 2.0, paginated | Full catalog (2002 -> now) via the REST API. Works with zero other setup, but slow and rate-limited. |
| `--mode days --days N` | NVD API 2.0, paginated | Only CVEs modified in the last N days (chunked into <=120-day windows, the API's own limit). The "keep an already-populated DT instance fresh" mode. Output is a single dated file: `./download/nvd/nvd_modified_<N>d-<date>.json`. |

## Usage

```bash
# One-time full bootstrap (fast, recommended)
python nvd_database_downloader.py --mode full --source zip

# Force re-download of every year, ignoring the unchanged-check
python nvd_database_downloader.py --mode full --source zip --force-full

# Full catalog via API instead (slow, no separate feed files needed)
python nvd_database_downloader.py --mode full --source api

# Keep a running instance fresh: CVEs modified in the last 2 days
python nvd_database_downloader.py --mode days --days 2

# Enable debug logging
python nvd_database_downloader.py --mode days --days 2 --debug
```

## API Key

Optional but strongly recommended: raises the NVD API rate limit from 5 to 50 requests per 30s
(`--mode full --source api` and `--mode days` both use the API; `--mode full --source zip` does
not need a key at all). Resolved in this order:

1. `--api-key` CLI flag
2. `NVD_API_KEY` environment variable
3. `nvd_api_key` in `./config.json` (copy `config.json.example` and fill in your key; `config.json`
   is gitignored)

## Proxy

`--proxy` CLI flag, see [Enterprise Proxy](#enterprise-proxy) above.

## Output Structure

```
download/nvd/
├── zip_feed_state.json          # Per-year lastModifiedDate, used to skip unchanged years
├── nvdcve-2.0-2002.json         # --source zip: one file per year, NVD's own naming
├── nvdcve-2.0-2003.json
├── ...
└── nvd_modified_2d-2026-07-25.json   # --mode days: one dated file per run
```

---

# CERT-FR Bulletin Downloader

Downloads every advisory (`avis`) and alert (`alerte`) published by CERT-FR
(cert.ssi.gouv.fr), one JSON file per bulletin (the site's own per-bulletin JSON payload,
unmodified).

## Usage

```bash
# Fetch both avis and alerte (default)
python cert_fr_fetch.py

# Only advisories, into a custom directory
python cert_fr_fetch.py --types avis --output /path/to/bulletins

# Slower crawl, gentler on the server
python cert_fr_fetch.py --delay 1.0
```

### Command Line Options

- `--output`: Output directory (default: `bulletins`)
- `--types`: Comma-separated bulletin types to fetch (default: `avis,alerte`)
- `--delay`: Delay between requests in seconds (default: `0.3`)
- `--proxy`: Proxy URL for all outbound requests (see [Enterprise Proxy](#enterprise-proxy))

## Incremental Updates

Each run lists every bulletin currently published for a type, then skips any reference already
present in that type's `current/` directory -- so a daily run only downloads bulletins that are
actually new. There is no separate timestamp/state file: the presence of the file itself is the
watermark.

## Output Structure

```
bulletins/
├── avis/
│   ├── current/                 # Every avis ever downloaded (grows over time)
│   │   ├── CERTFR-2026-AVI-0001.json
│   │   └── CERTFR-2026-AVI-0002.json
│   └── new/                     # Reset every run: only bulletins fetched in this run
│       └── CERTFR-2026-AVI-0002.json
└── alerte/
    ├── current/
    └── new/
```

`current/` is the cumulative mirror and also the delta reference (a bulletin already there is
never re-fetched). `new/` is emptied at the start of every run and ends up holding exactly the
bulletins added during that run -- convenient for feeding only "what's new today" into a
downstream pipeline without diffing `current/` yourself.