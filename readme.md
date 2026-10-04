***Vulnerability Database Downloaders***

Tools to download vulnerability data for use with Dependency-Track's offline mirroring, in the
same JSON/ZIP shapes DT already knows how to read.

- `osv_database_downloader.py` -- OSV (Open Source Vulnerabilities), per-ecosystem
- `nvd_database_downloader.py` -- NIST NVD, full catalog or recent changes
- `cert_fr_fetch.py` -- CERT-FR (French CERT) advisories and alerts
- `debian_security_fetch.py` -- Debian Security Advisories (DSA) and Debian LTS Advisories (DLA)
- `kevDownloader.py` -- Known Exploited Vulnerabilities catalogs: CISA KEV, ENISA EUVD KEV, VulnCheck KEV

## Output Layout

Every script writes under `./download/`, one directory per source:

```
download/
├── certfr/      # cert_fr_fetch.py           (avis/, alerte/ -> current/ + new/)
├── debian/      # debian_security_fetch.py   (dsa/, dla/   -> current/ + new/)
├── nvd/         # nvd_database_downloader.py
├── osv/         # osv_database_downloader.py (zip/ holds every {ecosystem}.zip to copy)
├── cisakev/     # kevDownloader.py
├── keveuvd/     # kevDownloader.py
└── vulncheck/   # kevDownloader.py
```

Nothing already downloaded is downloaded again:

- **certfr / debian**: `current/` always holds 100% of the advisories ever fetched; a reference
  already there is never re-fetched. `new/` is emptied at the start of every run and only holds
  what that run added -- it is safe to delete its content at any time (never delete `current/`,
  that is what tells the script what it already has).
- **nvd**: `--source zip` skips years whose `.meta` is unchanged; `--mode update` only asks the
  API for CVEs modified since the last successful API run.
- **osv**: per-ecosystem watermark, only changed advisories are fetched after the first run.
- **cisakev / keveuvd**: full dumps (the sources offer nothing finer), fetched with a conditional
  request (`ETag` / `Last-Modified`) so an unchanged catalog is not re-downloaded.
- **vulncheck**: the API has no conditional request, so the catalog is re-paginated each run;
  the file is only rewritten if its content changed.

## Enterprise Proxy

All tools work identically behind a corporate proxy, and require no configuration at all
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
python debian_security_fetch.py --proxy http://user:pass@proxy.company.com:8080
```

## API Keys (`kevDownloader.py`)

`kevDownloader.py` downloads the CISA KEV catalog
(`download/cisakev/known_exploited_vulnerabilities.json`), the ENISA EUVD KEV dump
(`download/keveuvd/euvd_kev.json`) and the VulnCheck KEV (`download/vulncheck/vulncheck_kev.json`,
requires an API key). The VulnCheck key is resolved in this order:

1. `VULNCHECK_API_KEY` environment variable
2. `vulncheck_api_key` in `./config.json` (see `config.json.example`)

`proxy` in `./config.json` is honored as well (see [Enterprise Proxy](#enterprise-proxy)).

If none is set, VulnCheck is skipped and only CISA and EUVD are downloaded.

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
├── zip/                        # Everything to copy to the Dependency-Track machine
│   ├── PyPI.zip                # PyPI advisories: full DB on first run, changed-only afterwards
│   ├── npm.zip                 # npm advisories: full DB on first run, changed-only afterwards
│   └── ...                     # Other ecosystem ZIP files
├── PyPI/                       # Per-ecosystem directories
│   └── modified_id.csv         # PyPI-specific modified vulnerabilities
├── npm/
│   └── modified_id.csv         # npm-specific modified vulnerabilities
└── ...
```

`{ecosystem}.zip` is always named exactly that (never a dated/versioned filename) --
Dependency-Track's offline OSV reader looks for that fixed name and deletes it once it has
successfully mirrored its contents. All of them live in `download/osv/zip/`, so that single
directory is what you copy to the target machine.

If a `zip/{ecosystem}.zip` from a previous run is still there (not yet copied/consumed), a new
incremental run merges the changed advisories into it instead of overwriting it, so no advisory
is lost between two copies. Once copied, delete the zips from `zip/`: the next run will only
contain what changed since.

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
- If a previous `{ecosystem}.zip` has not been consumed yet, the changed advisories are merged into it
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
| `--mode days --days N` | NVD API 2.0, paginated | Only CVEs modified in the last N days (chunked into <=120-day windows, the API's own limit). Output is a single dated file: `./download/nvd/nvd_modified_<N>d-<date>.json`. |
| `--mode update` (recommended for scheduled runs) | NVD API 2.0, paginated | Only CVEs modified since the last successful API run (`full`, `days` or `update`), recorded in `download/nvd/api_state.json` -- nothing already fetched is fetched again, whatever the interval between runs. Needs one prior API run, or `--days N` as a fallback for the very first one. Output: `./download/nvd/nvd_update-<date>T<time>.json`. |

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

# Scheduled runs: only what changed since the previous run (falls back to 2 days the first time)
python nvd_database_downloader.py --mode update --days 2

# Enable debug logging
python nvd_database_downloader.py --mode days --days 2 --debug
```

## API Key

Optional but strongly recommended: raises the NVD API rate limit from 5 to 50 requests per 30s
(`--mode full --source api`, `--mode days` and `--mode update` use the API; `--mode full --source zip` does
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
├── api_state.json               # Last successful API run, watermark for --mode update
├── nvdcve-2.0-2002.json         # --source zip: one file per year, NVD's own naming
├── nvdcve-2.0-2003.json
├── ...
├── nvd_modified_2d-2026-07-25.json   # --mode days: one dated file per run
└── nvd_update-2026-07-25T061500.json # --mode update: one timestamped file per run
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

# Walk the whole listing again (e.g. to pick up anything missed); existing files are still skipped
python cert_fr_fetch.py --full
```

### Command Line Options

- `--output`: Output directory (default: `download/certfr`)
- `--types`: Comma-separated bulletin types to fetch (default: `avis,alerte`)
- `--full`: Walk every listing page instead of stopping at the first already-downloaded page
- `--delay`: Delay between requests in seconds (default: `0.3`)
- `--proxy`: Proxy URL for all outbound requests (see [Enterprise Proxy](#enterprise-proxy))

## Incremental Updates

A reference already present in a type's `current/` directory is never re-fetched: the presence
of the file itself is the watermark.

The listing is published newest first, so after the first complete walk (recorded by a
`listing_complete` marker), each run stops paging at the first listing page whose references are
all already in `current/` -- a daily run typically reads one or two listing pages, not hundreds.
Bulletins whose download failed are recorded in `failed.json` and retried directly on the next
run. `--full` forces a complete walk (still without re-downloading anything already there).

Revisions of an already-downloaded bulletin (same reference, updated content) are not
re-fetched.

## Output Structure

```
download/certfr/
├── avis/
│   ├── listing_complete         # A full listing walk has completed at least once
│   ├── failed.json              # References to retry next run
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

---

# Debian Security Advisory (DSA/DLA) Downloader

Downloads Debian Security Advisories (DSA) and Debian LTS Advisories (DLA) from the Debian
Security Tracker's own machine-readable list files (`data/DSA/list`, `data/DLA/list` on
salsa.debian.org) -- the same source Debian itself uses to generate debian.org/security.
One JSON file per advisory, with the package name, CVE list, and every fixed version per Debian
release (suite codename) the advisory applies to.

## Usage

```bash
# Fetch both DSA and DLA (default)
python debian_security_fetch.py

# Only DSA, into a custom directory
python debian_security_fetch.py --types dsa --output /path/to/debian

# Only advisories published in the last 2 days -- for a daily/scheduled run, or a first
# bootstrap where you don't want years of history
python debian_security_fetch.py --days 2

python debian_security_fetch.py --proxy http://user:pass@proxy.company.com:8080
```

### Command Line Options

- `--output`: Output directory (default: `download/debian`)
- `--types`: Comma-separated advisory types to fetch (default: `dsa,dla`)
- `--days`: Only keep advisories published in the last N days (default: no limit, full history).
  This only limits what gets written to `current/`/`new/`.
- `--proxy`: Proxy URL for all outbound requests (see [Enterprise Proxy](#enterprise-proxy))

## Incremental Updates

Same convention as CERT-FR: each advisory ID already present in `current/` is never re-fetched or
re-parsed, so a daily run only writes what's actually new. There is no separate timestamp/state
file -- the presence of the file itself is the watermark. A revised advisory gets a new ID
(`DSA-6455-2` replacing `DSA-6455-1`) and is naturally treated as new, not skipped as a duplicate.

The list file itself is fetched with a conditional request (`ETag` / `Last-Modified`, kept in
`<type>/http_state.json`): if it has not changed since the last run, it is not downloaded again.

## Output Structure

```
download/debian/
├── dsa/
│   ├── http_state.json          # ETag / Last-Modified of the last fetched list
│   ├── current/                 # Every DSA ever downloaded (grows over time)
│   │   ├── DSA-6455-1.json
│   │   └── DSA-6454-1.json
│   └── new/                     # Reset every run: only advisories fetched in this run
│       └── DSA-6455-1.json
└── dla/
    ├── current/
    └── new/
```

## Advisory JSON Shape

```json
{
  "id": "DSA-6455-1",
  "type": "DSA",
  "date": "20 Aug 2026",
  "package": "chromium",
  "title": "security update",
  "cves": ["CVE-2026-76033", "CVE-2026-76034"],
  "fixes": [
    {"release": "trixie", "package": "chromium", "version": "151.0.7922.169-1~deb13u1"}
  ]
}
```

`fixes` can hold more than one entry when the same advisory was backported to multiple Debian
releases (e.g. `bullseye` and `bookworm` for the same DLA) -- each with its own fixed version,
since Debian releases carry independent version numbering per suite. `cves` is empty (not absent)
for the advisories that don't reference a CVE yet.

## Downstream matching (not done by this script)

This script only fetches and normalizes the raw advisory data -- it does not talk to
Dependency-Track. Turning these JSON files into vulnerability matches against components requires
a parser that builds a PURL per `fixes` entry
(`pkg:deb/debian/<package>@<version>?distro=debian-<release>`, or `pkg:deb/ubuntu/...` for an
Ubuntu equivalent) and feeds it through DT's existing Debian-aware version comparator -- not
written yet. The `dependency-track` repo's `vuln-data-source/certfr/` module (a Maven plugin:
`CertFRVulnDataSource`, `CertFRVulnDataSourceFactory`, `CertFRVulnDataSourcePlugin`,
`CertFRModelConverter`) is the pattern this fork already uses for turning an offline-mirrored
directory of JSON files into `VulnerableSoftware` rows -- a `vuln-data-source/debian/` module
following the same shape is the next step.