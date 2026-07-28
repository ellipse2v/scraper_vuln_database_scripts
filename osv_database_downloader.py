"""
Copyright (C) 2024 ellipse2v (ellipse2v@gmail.com)

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

import requests
import logging
import urllib
import os
import re
import json
import zipfile
import argparse
from datetime import datetime, timezone

# list of ecosystem
CONST_URL_ECOSYSTEM = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"
CONST_URL_OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com/"
CONST_URL_GLOBAL_MODIFIED = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
list_ecosystem = []

OUTPUT_DIR = "./download/osv"
CONFIG_FILE = "./config.json"

# File to track last download timestamps / per-ecosystem incremental state
TIMESTAMP_TRACKER_FILE = f"{OUTPUT_DIR}/timestamps.json"

SESSION = requests.Session()

# Mirrors org.dependencytrack.vulndatasource.osv.OsvVulnDataSource's own threshold: above this
# many changed advisories, a full re-download is cheaper (and simpler) than that many individual
# per-advisory HTTP requests.
CONST_MAX_INCREMENTAL_ADVISORY_DOWNLOADS = 250

_TIMESTAMP_RE = re.compile(r"^(?P<base>.*T\d\d:\d\d:\d\d)(?P<frac>\.\d+)?(?P<tz>Z)?$")


def load_config():
    """Load config.json if present. Returns {} if missing -- all keys are optional."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Failed to load {CONFIG_FILE}: {e}")
    return {}


def resolve_proxy(args, config):
    """Resolve an explicit proxy override, in order: --proxy CLI flag > config.json 'proxy'
    key. Returns None if neither is set -- the Session's default trust_env=True then keeps
    consulting the usual HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables on its own, so
    an unconfigured proxy is a no-op, not broken behavior."""
    if args.proxy:
        return args.proxy
    return config.get("proxy")


def readOSVecosystem(response):
    # Create download directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(f"{OUTPUT_DIR}/osv_ecosystems.txt", "wb") as fichier:
        fichier.write(response.content)
        fichier.close()
        fichier = open(f"{OUTPUT_DIR}/osv_ecosystems.txt", "r")
        lines = fichier.read().splitlines()
        fichier.close()

        list_ecosystem.extend(lines)


def load_timestamps():
    """Load previously stored timestamps from file"""
    if os.path.exists(TIMESTAMP_TRACKER_FILE):
        try:
            with open(TIMESTAMP_TRACKER_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Failed to load timestamps: {e}")
    return {}


def save_timestamps(timestamps):
    """Save timestamps to file"""
    try:
        with open(TIMESTAMP_TRACKER_FILE, "w") as f:
            json.dump(timestamps, f, indent=2)
    except IOError as e:
        logging.error(f"Failed to save timestamps: {e}")


def parse_osv_timestamp(value):
    """Parse an OSV modified_id.csv timestamp (ISO-8601, 'Z'-suffixed, up to nanosecond
    precision) into an aware datetime. Python's fromisoformat only accepts up to microsecond
    precision, so any extra fractional digits are truncated rather than rejected."""
    match = _TIMESTAMP_RE.match(value)
    if not match:
        raise ValueError(f"Unrecognized timestamp format: {value}")
    base = match.group("base")
    frac = match.group("frac") or ""
    return datetime.fromisoformat(base + frac[:7] + "+00:00")


def download_global_modified_file():
    """Download the global modified_id.csv file"""
    logging.info("Downloading global modified_id.csv file")

    try:
        response = SESSION.get(CONST_URL_GLOBAL_MODIFIED)
        response.raise_for_status()

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(f"{OUTPUT_DIR}/global_modified_id.csv", "wb") as fichier:
            fichier.write(response.content)

        logging.info("Successfully downloaded global modified_id.csv")
        return True

    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to download global modified_id.csv: {e}")
        return False
    except Exception as e:
        logging.error(f"Exception while downloading global modified_id.csv: {e}")
        return False


def download_ecosystem_modified_file(ecosystem):
    """Download the modified_id.csv file for a specific ecosystem.

    Returns the file's text content on success (also persisted to disk for inspection/
    debugging), or None on failure.
    """
    logging.info(f"Downloading modified_id.csv for ecosystem: {ecosystem}")

    # Construct URL for ecosystem-specific modified_id.csv
    url = f"https://storage.googleapis.com/osv-vulnerabilities/{urllib.parse.quote(ecosystem, encoding='utf-8')}/modified_id.csv"

    try:
        response = SESSION.get(url)
        response.raise_for_status()

        # Create ecosystem directory if it doesn't exist
        ecosystem_dir = f"{OUTPUT_DIR}/{ecosystem}"
        os.makedirs(ecosystem_dir, exist_ok=True)

        with open(f"{ecosystem_dir}/modified_id.csv", "wb") as fichier:
            fichier.write(response.content)

        logging.info(f"Successfully downloaded modified_id.csv for {ecosystem}")
        return response.text

    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to download modified_id.csv for {ecosystem}: {e}")
        return None
    except Exception as e:
        logging.warning(f"Exception while downloading modified_id.csv for {ecosystem}: {e}")
        return None


def parse_modified_ids_since(csv_text, since):
    """Return the list of vulnerability IDs modified after `since`.

    modified_id.csv is published sorted by timestamp descending (most recent first), so -- same
    as DT's own OsvVulnDataSource#getModifiedIds -- this stops at the first entry that is not
    newer than `since` rather than scanning the whole (possibly tens-of-thousands-of-lines) file.
    """
    modified_ids = []
    for line in csv_text.splitlines():
        if not line:
            continue
        parts = line.split(",", 1)
        if len(parts) != 2:
            raise ValueError(f"Malformed modified_id.csv line: {line!r}")
        timestamp_str, vuln_id = parts
        if parse_osv_timestamp(timestamp_str) > since:
            modified_ids.append(vuln_id)
            if len(modified_ids) > CONST_MAX_INCREMENTAL_ADVISORY_DOWNLOADS:
                break
        else:
            break
    return modified_ids


def fetch_advisory(ecosystem, vuln_id):
    """Download a single advisory's JSON content. Returns bytes on success, None on failure
    (logged as a warning -- an ID listed in modified_id.csv could in rare cases disappear
    between listing and fetch)."""
    url = f"{CONST_URL_OSV_BASE}{urllib.parse.quote(ecosystem, encoding='utf-8')}/{urllib.parse.quote(vuln_id, encoding='utf-8')}.json"
    try:
        response = SESSION.get(url)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to download advisory {vuln_id} for {ecosystem}: {e}")
        return None


def write_delta_zip(zip_path, id_to_content):
    """Write a zip archive containing one `{vuln_id}.json` entry per advisory. DT's offline OSV
    reader (ZipOsvAdvisorySource) reads every non-directory `*.json` entry in the archive
    independently, regardless of whether the archive holds a full or partial advisory set -- so
    this is format-compatible with the official `all.zip` files DT also accepts."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for vuln_id, content in id_to_content.items():
            zf.writestr(f"{vuln_id}.json", content)


def download_full_ecosystem_zip(ecosystem):
    """Download the complete `all.zip` for `ecosystem` into `{OUTPUT_DIR}/{ecosystem}.zip`
    (the exact filename DT's offline OSV reader looks for). Returns True on success."""
    url = f"{CONST_URL_OSV_BASE}{urllib.parse.quote(ecosystem, encoding='utf-8').replace(' ', '%20')}/all.zip"

    try:
        response = SESSION.get(url)
        response.raise_for_status()

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(f"{OUTPUT_DIR}/{ecosystem}.zip", "wb") as fichier:
            fichier.write(response.content)

        logging.info(f"✓ Downloaded full {ecosystem} database")
        return True

    except requests.exceptions.RequestException as e:
        logging.error(f"✗ Download failed for {ecosystem}: {e}")
        return False
    except Exception as e:
        logging.error(f"✗ Exception downloading {ecosystem}: {e}")
        return False


def process_ecosystem(ecosystem, eco_state, force_full):
    """Download whatever DT needs for `ecosystem` -- a full archive on first run, `--force-full`,
    or when there are too many changes to fetch individually; otherwise just the advisories that
    changed since the last successful run, packaged the same way. Both cases write to
    `{OUTPUT_DIR}/{ecosystem}.zip`, since that is the single, fixed filename DT's offline OSV
    reader looks for (see OsvVulnDataSource#openOfflineArchive) -- there is no "dated snapshot"
    naming convention for OSV like there is for KEV/EPSS/NVD.

    Returns the new per-ecosystem state dict (to be persisted) on success, or None if nothing
    should be persisted (failure, or no changes to apply).
    """
    # Captured before any network I/O: used as the new watermark on success, so that anything
    # modified upstream *during* this run is simply picked up again on the next run rather than
    # silently skipped.
    run_start = datetime.now(timezone.utc)

    is_first_run = eco_state is None or "last_success" not in eco_state
    if force_full or is_first_run:
        if download_full_ecosystem_zip(ecosystem):
            return {"last_success": run_start.isoformat()}
        return None

    since = datetime.fromisoformat(eco_state["last_success"])

    modified_csv = download_ecosystem_modified_file(ecosystem)
    if modified_csv is None:
        logging.warning(f"Could not check {ecosystem} for changes; leaving state unchanged")
        return None

    try:
        changed_ids = parse_modified_ids_since(modified_csv, since)
    except ValueError as e:
        logging.error(f"Could not parse modified_id.csv for {ecosystem}: {e}")
        return None

    if not changed_ids:
        logging.info(f"No changes for {ecosystem} since {since.isoformat()}")
        return {"last_success": run_start.isoformat()}

    if len(changed_ids) > CONST_MAX_INCREMENTAL_ADVISORY_DOWNLOADS:
        logging.info(
            f"{len(changed_ids)} changed advisories for {ecosystem} exceeds the incremental "
            f"threshold of {CONST_MAX_INCREMENTAL_ADVISORY_DOWNLOADS}; downloading the full "
            f"database instead")
        if download_full_ecosystem_zip(ecosystem):
            return {"last_success": run_start.isoformat()}
        return None

    logging.info(f"Fetching {len(changed_ids)} changed advisories for {ecosystem}")
    advisories = {}
    for vuln_id in changed_ids:
        content = fetch_advisory(ecosystem, vuln_id)
        if content is not None:
            advisories[vuln_id] = content

    if not advisories:
        logging.warning(f"Failed to fetch any changed advisories for {ecosystem}; leaving state unchanged")
        return None

    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        write_delta_zip(f"{OUTPUT_DIR}/{ecosystem}.zip", advisories)
    except IOError as e:
        logging.error(f"Failed to write delta archive for {ecosystem}: {e}")
        return None

    logging.info(f"✓ Wrote {len(advisories)} changed advisories for {ecosystem}")
    return {"last_success": run_start.isoformat()}


def downloadOSVdata(force_full=False):
    """Download OSV data with support for both full and incremental modes.

    Incremental state is tracked per ecosystem (not a single global flag), so adding a new
    ecosystem later gets its own full download while already-tracked ecosystems keep receiving
    true incremental updates.
    """
    if not list_ecosystem:
        logging.info("Google OSV mirroring is disabled. No ecosystem selected.")
        return

    state = load_timestamps()
    ecosystem_state = state.setdefault("ecosystems", {})

    # Always download modified_id.csv files for tracking
    download_global_modified_file()

    for ecosystem in list_ecosystem:
        logging.info(f"Processing ecosystem: {ecosystem}")

        new_state = process_ecosystem(ecosystem, ecosystem_state.get(ecosystem), force_full)
        if new_state is not None:
            ecosystem_state[ecosystem] = new_state
            save_timestamps(state)


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='OSV Database Downloader with incremental update support')
    parser.add_argument('--force-full', action='store_true',
                       help='Force full download of all data (ignore timestamps)')
    parser.add_argument('--incremental', action='store_true',
                       help='Perform incremental update only (default behavior)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    parser.add_argument('--proxy',
                       help='Proxy URL for all outbound requests, e.g. http://user:pass@proxy.company.com:8080 '
                            '(overrides config.json / HTTP_PROXY / HTTPS_PROXY)')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    proxy = resolve_proxy(args, load_config())
    if proxy:
        SESSION.proxies.update({"http": proxy, "https": proxy})

    logging.info(f"Starting OSV database download - Run ID: {datetime.now(timezone.utc).isoformat()}")
    logging.info(f"Force full download: {args.force_full}")

    response = SESSION.get(CONST_URL_ECOSYSTEM)
    if response.status_code == 200:
        readOSVecosystem(response)
        logging.info(f"Found {len(list_ecosystem)} ecosystems: {list_ecosystem[:5]}...")  # Show first 5

        downloadOSVdata(force_full=args.force_full)

        logging.info("Download completed successfully")
    else:
        logging.error(f"Failed to download ecosystem list: {response.status_code}")
        exit(1)

if __name__ == "__main__":
    main()
