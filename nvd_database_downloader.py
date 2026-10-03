"""
Copyright (C) 2026 ellipse2v (ellipse2v@gmail.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

"""
NVD Database Downloader

Downloads NVD CVE data in one of three modes, all producing output in the same
JSON shape as the NVD API 2.0 response (resultsPerPage/startIndex/totalResults/
format/version/timestamp/vulnerabilities[].cve...) -- the same shape used by
Dependency-Track's offline NVD import (nvdcve-2.0-<year>.json / .../modified.json).

Modes:
  --mode full --source api   Paginate the full NVD API 2.0 catalog (2002 -> now).
                              Slow (rate-limited), but works with no other setup.
  --mode full --source zip   Download the official yearly nvdcve-2.0-<year>.json.zip
                              feeds (https://nvd.nist.gov/feeds/json/cve/2.0/). Much
                              faster for a full historical bootstrap. Content is
                              already in the target JSON shape -- no conversion,
                              files are written using NVD's own per-year naming so
                              Dependency-Track's offline mode picks them up natively.
                              Uses each feed's .meta file to skip years that have not
                              changed since the last run.
  --mode days --days N        Fetch only CVEs modified in the last N days via the API
                              (chunked into <=120-day windows, the API's own limit),
                              merged into a single dated output file -- the delta/
                              "keep an already-populated DT instance fresh" mode.

API key (optional but strongly recommended -- raises the rate limit from 5 to 50
requests per 30s): put it in config.json (see config.json.example), or pass
--api-key, or set the NVD_API_KEY environment variable.
"""

import argparse
import json
import logging
import os
import time
import zipfile
from datetime import datetime, timedelta, timezone

import requests

CONST_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CONST_FEEDS_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
CONST_API_PAGE_SIZE = 2000
CONST_API_MAX_DATE_RANGE_DAYS = 120  # Hard limit enforced by the NVD API itself.
CONST_FIRST_CVE_YEAR = 2002

CONFIG_FILE = "./config.json"
OUTPUT_DIR = "./download/nvd"
ZIP_STATE_FILE = f"{OUTPUT_DIR}/zip_feed_state.json"

SESSION = requests.Session()


def load_config():
    """Load config.json if present. Returns {} if missing -- all keys are optional."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Failed to load {CONFIG_FILE}: {e}")
    return {}


def resolve_api_key(args, config):
    if args.api_key:
        return args.api_key
    if os.environ.get("NVD_API_KEY"):
        return os.environ["NVD_API_KEY"]
    if config.get("nvd_api_key"):
        return config["nvd_api_key"]
    return None


def resolve_proxy(args, config):
    """Resolve an explicit proxy override, in order: --proxy CLI flag > config.json 'proxy'
    key. Returns None if neither is set -- the Session's default trust_env=True then keeps
    consulting the usual HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables on its own, so
    an unconfigured proxy is a no-op, not broken behavior."""
    if args.proxy:
        return args.proxy
    return config.get("proxy")


def throttle_delay(api_key):
    """
    NVD API 2.0 public rate limits: 5 requests/30s without a key, 50 requests/30s
    with one. Sleep a little longer than the strict minimum to leave headroom.
    """
    return 0.7 if api_key else 6.5


def fetch_api_page(api_key, params):
    headers = {"apiKey": api_key} if api_key else {}
    response = SESSION.get(CONST_API_BASE, params=params, headers=headers, timeout=60)
    if response.status_code == 403:
        raise RuntimeError(
            "NVD API returned 403 Forbidden -- likely rate-limited or an invalid API key")
    response.raise_for_status()
    return response.json()


def fetch_api_range(api_key, extra_params=None, label="full catalog"):
    """
    Paginate the NVD API 2.0 catalog and merge all pages into a single result dict
    with the same top-level shape as a single page's response.
    """
    extra_params = extra_params or {}
    all_vulnerabilities = []
    start_index = 0
    total_results = None
    meta = {}

    while total_results is None or start_index < total_results:
        params = {
            "resultsPerPage": CONST_API_PAGE_SIZE,
            "startIndex": start_index,
            **extra_params,
        }
        logging.info(f"Fetching {label}: startIndex={start_index}"
                     + (f"/{total_results}" if total_results is not None else ""))

        page = fetch_api_page(api_key, params)
        total_results = page.get("totalResults", 0)
        meta = {
            "format": page.get("format"),
            "version": page.get("version"),
        }
        all_vulnerabilities.extend(page.get("vulnerabilities", []))
        start_index += CONST_API_PAGE_SIZE

        if start_index < total_results:
            time.sleep(throttle_delay(api_key))

    return {
        "resultsPerPage": len(all_vulnerabilities),
        "startIndex": 0,
        "totalResults": len(all_vulnerabilities),
        "format": meta.get("format", "NVD_CVE"),
        "version": meta.get("version", "2.0"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vulnerabilities": all_vulnerabilities,
    }


def download_full_via_api(api_key):
    logging.info("Downloading full NVD catalog via API (no date filter)")
    result = fetch_api_range(api_key, label="full catalog")
    write_output(result, "nvd_full_vulnerabilities")


def download_days_via_api(api_key, days):
    """
    NVD restricts a single lastMod date-range query to at most 120 days, so a
    request for more than that is chunked into consecutive <=120-day windows and
    merged into one output file.
    """
    logging.info(f"Downloading NVD CVEs modified in the last {days} day(s) via API")

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    all_vulnerabilities = []
    meta = {}
    window_start = start
    while window_start < end:
        window_end = min(window_start + timedelta(days=CONST_API_MAX_DATE_RANGE_DAYS), end)
        # NVD requires the colon-separated ISO-8601 offset ("+00:00"); Python's %z produces
        # "+0000", which the API rejects outright with a 404. window_start/window_end are always
        # UTC (derived from datetime.now(timezone.utc)), so the offset is hardcoded rather than
        # formatted from the datetime's own tzinfo.
        params = {
            "lastModStartDate": window_start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "lastModEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        }
        chunk = fetch_api_range(
            api_key, extra_params=params,
            label=f"{window_start.date()} -> {window_end.date()}")
        all_vulnerabilities.extend(chunk["vulnerabilities"])
        meta = {"format": chunk["format"], "version": chunk["version"]}
        window_start = window_end

    result = {
        "resultsPerPage": len(all_vulnerabilities),
        "startIndex": 0,
        "totalResults": len(all_vulnerabilities),
        "format": meta.get("format", "NVD_CVE"),
        "version": meta.get("version", "2.0"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vulnerabilities": all_vulnerabilities,
    }
    write_output(result, f"nvd_modified_{days}d")


def write_output(result, name_prefix):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    out_path = f"{OUTPUT_DIR}/{name_prefix}-{date_str}.json"
    with open(out_path, "w") as f:
        json.dump(result, f)
    logging.info(f"Wrote {result['totalResults']} CVE(s) to {out_path}")


# ---------------------------------------------------------------------------
# Zip feed mode
# ---------------------------------------------------------------------------

def load_zip_state():
    if os.path.exists(ZIP_STATE_FILE):
        try:
            with open(ZIP_STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Failed to load {ZIP_STATE_FILE}: {e}")
    return {}


def save_zip_state(state):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(ZIP_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def parse_meta(meta_text):
    """The .meta file is a small set of `key:value` lines, e.g. lastModifiedDate:..."""
    result = {}
    for line in meta_text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return result


def download_zip_feeds(force_full):
    """
    Download the official per-year nvdcve-2.0-<year>.json.zip feeds directly into
    OUTPUT_DIR, unzipped, using NVD's own filenames -- Dependency-Track's offline
    mode already recognizes "nvdcve-2.0-<year>.json" exactly, so these can be
    pointed at directly with no renaming or merging.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    state = {} if force_full else load_zip_state()
    current_year = datetime.now().year

    for year in range(CONST_FIRST_CVE_YEAR, current_year + 1):
        meta_url = f"{CONST_FEEDS_BASE}/nvdcve-2.0-{year}.meta"
        zip_url = f"{CONST_FEEDS_BASE}/nvdcve-2.0-{year}.json.zip"

        try:
            meta_response = SESSION.get(meta_url, timeout=30)
            meta_response.raise_for_status()
            meta = parse_meta(meta_response.text)
        except requests.exceptions.RequestException as e:
            logging.warning(f"Failed to fetch meta for {year}: {e}")
            continue

        last_modified = meta.get("lastModifiedDate")
        if not force_full and state.get(str(year)) == last_modified:
            logging.info(f"Skipping {year}: unchanged since last run ({last_modified})")
            continue

        logging.info(f"Downloading nvdcve-2.0-{year}.json.zip ({last_modified})")
        try:
            zip_response = SESSION.get(zip_url, timeout=300)
            zip_response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to download {zip_url}: {e}")
            continue

        zip_path = f"{OUTPUT_DIR}/nvdcve-2.0-{year}.json.zip"
        with open(zip_path, "wb") as f:
            f.write(zip_response.content)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(OUTPUT_DIR)
        os.remove(zip_path)

        state[str(year)] = last_modified
        save_zip_state(state)
        logging.info(f"✓ {year} extracted to {OUTPUT_DIR}/nvdcve-2.0-{year}.json")


def main():
    parser = argparse.ArgumentParser(description="NVD CVE database downloader")
    parser.add_argument("--mode", choices=["full", "days"], required=True,
                         help="'full': entire catalog. 'days': only CVEs modified in the last N days.")
    parser.add_argument("--source", choices=["api", "zip"], default="api",
                         help="'api': NVD API 2.0 (works for both modes). "
                              "'zip': official yearly feed files (only valid with --mode full).")
    parser.add_argument("--days", type=int, help="Number of days back to fetch (required for --mode days).")
    parser.add_argument("--force-full", action="store_true",
                         help="For --source zip: re-download every year, ignoring the local unchanged-check.")
    parser.add_argument("--api-key", help="NVD API key (overrides config.json / NVD_API_KEY env var).")
    parser.add_argument("--proxy",
                         help="Proxy URL for all outbound requests, e.g. http://user:pass@proxy.company.com:8080 "
                              "(overrides config.json / HTTP_PROXY / HTTPS_PROXY)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    if args.mode == "days" and not args.days:
        parser.error("--mode days requires --days N")
    if args.mode == "days" and args.source == "zip":
        parser.error("--source zip only supports --mode full (the yearly feeds are not date-filterable)")

    config = load_config()
    proxy = resolve_proxy(args, config)
    if proxy:
        SESSION.proxies.update({"http": proxy, "https": proxy})

    api_key = resolve_api_key(args, config)
    if not api_key and args.source == "api":
        logging.warning(
            "No NVD API key configured -- proceeding unauthenticated (5 req/30s, much slower). "
            "See config.json.example.")

    if args.mode == "full" and args.source == "zip":
        download_zip_feeds(force_full=args.force_full)
    elif args.mode == "full":
        download_full_via_api(api_key)
    else:
        download_days_via_api(api_key, args.days)

    logging.info("Done")


if __name__ == "__main__":
    main()
