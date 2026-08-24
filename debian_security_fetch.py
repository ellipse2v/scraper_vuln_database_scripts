#!/usr/bin/env python3
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

"""Fetches Debian Security Advisories (DSA) and Debian LTS Advisories (DLA) from the Debian
Security Tracker's own machine-readable list files, and saves one JSON file per advisory.

Source format (data/DSA/list, data/DLA/list -- same syntax for both, tab-indented):

    [20 Aug 2026] DSA-6455-1 chromium - security update
        {CVE-2026-76033 CVE-2026-76034}
        [trixie] - chromium 151.0.7922.169-1~deb13u1

The CVE line is optional (some advisories have none yet, or none at all). One or more release
lines can follow (backports across multiple suites, e.g. bookworm + trixie for the same DSA).

This is the same list the Debian Security Tracker itself uses to generate https://www.debian.org/security/ --
authoritative, stable, and does not require scraping HTML pages one at a time like CERT-FR does.
"""

import argparse
import json
import os
import re
from datetime import date, datetime, timedelta
from pathlib import Path

import requests

BASE_URL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data"
LIST_URL = {
    "dsa": f"{BASE_URL}/DSA/list",
    "dla": f"{BASE_URL}/DLA/list",
}

HEADER_RE = re.compile(
    r"^\[(?P<date>\d{1,2} \w+ \d{4})\]\s+(?P<id>\S+)\s+(?P<package>\S+)\s+-\s+(?P<title>.+)$"
)
CVE_LINE_RE = re.compile(r"^\{(?P<cves>.+)\}$")
# Trailing "(...)" is an optional free-text annotation seen on older (pre-~2010) entries --
# a severity ("(high)"), a bug reference ("(bug #302701)"), or a note on why a <marker> version
# applies ("(Vulnerable code not present)"). Not part of the version; discarded if present.
RELEASE_LINE_RE = re.compile(
    r"^\[(?P<release>[\w-]+)\]\s+-\s+(?P<package>\S+)\s+(?P<version>\S+)(?:\s+\(.*\))?$"
)

# Matches the "date" field this script itself writes into each advisory (HEADER_RE's capture,
# e.g. "20 Aug 2026") -- used only for --days filtering, not for parsing the upstream file.
ADVISORY_DATE_FORMAT = "%d %b %Y"

CONFIG_FILE = "./config.json"

SESSION = requests.Session()


def load_config() -> dict:
    """Load config.json if present. Returns {} if missing -- all keys are optional."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: failed to load {CONFIG_FILE}: {e}")
    return {}


def resolve_proxy(args, config: dict):
    """Resolve an explicit proxy override, in order: --proxy CLI flag > config.json 'proxy'
    key. Returns None if neither is set -- the Session's default trust_env=True then keeps
    consulting the usual HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables on its own, so
    an unconfigured proxy is a no-op, not broken behavior."""
    if args.proxy:
        return args.proxy
    return config.get("proxy")


def fetch_list(advisory_type: str) -> str:
    resp = SESSION.get(LIST_URL[advisory_type], timeout=60)
    resp.raise_for_status()
    return resp.text


def parse_list(text: str, advisory_type: str) -> list[dict]:
    """Parses the whole list file into one record per advisory.

    Blank lines separate nothing in particular (the format doesn't use them consistently) --
    a new record starts whenever a header line is seen, so blank/unexpected lines between
    records are simply skipped rather than treated as errors.
    """
    advisories = []
    current = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        if not line.strip():
            continue

        header = HEADER_RE.match(line)
        if header:
            if current:
                advisories.append(current)
            current = {
                "id": header.group("id"),
                "type": advisory_type.upper(),
                "date": header.group("date"),
                "package": header.group("package"),
                "title": header.group("title"),
                "cves": [],
                "fixes": [],
            }
            continue

        if current is None:
            # Line before any header line was seen -- not a valid advisory body line, skip.
            continue

        stripped = line.strip()

        cve_line = CVE_LINE_RE.match(stripped)
        if cve_line:
            current["cves"] = cve_line.group("cves").split()
            continue

        release_line = RELEASE_LINE_RE.match(stripped)
        if release_line:
            version = release_line.group("version")
            # Debian's list format uses bracketed markers instead of a real version when there
            # is nothing to point a fix at, e.g. "[jessie] - elasticsearch <end-of-life>" (also
            # seen: <not-affected>, <unfixed>). Not a version string -- skip the entry.
            if version.startswith("<") and version.endswith(">"):
                continue
            current["fixes"].append({
                "release": release_line.group("release"),
                "package": release_line.group("package"),
                "version": version,
            })
            continue

        # Unrecognized body line (e.g. a "NOTE:" or free-text line the format occasionally
        # carries) -- not fatal, just not structured data we extract.

    if current:
        advisories.append(current)

    return advisories


def parse_advisory_date(date_str: str) -> date | None:
    """Parses an advisory's "20 Aug 2026"-style date field. Returns None (rather than raising)
    on an unexpected format, so one oddly-formatted upstream entry can't crash the whole run --
    the caller treats None as "keep it" (fail open: --days is a convenience filter, not a
    correctness guarantee, so an unparseable date should not silently drop an advisory)."""
    try:
        return datetime.strptime(date_str, ADVISORY_DATE_FORMAT).date()
    except ValueError:
        return None


def reset_new_dir(new_dir: Path) -> None:
    """Empty `new_dir` so it only ever holds this run's newly fetched advisories."""
    if new_dir.exists():
        for f in new_dir.iterdir():
            f.unlink()
    else:
        new_dir.mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="debian", help="Output directory")
    parser.add_argument("--types", default="dsa,dla", help="Advisory types to fetch (dsa,dla)")
    parser.add_argument("--days", type=int, default=None,
                         help="Only keep advisories published in the last N days (default: no "
                              "limit, full history). The upstream list is still fetched in full "
                              "either way -- it's a single small file -- this only limits what "
                              "gets written to current/new.")
    parser.add_argument("--proxy",
                         help="Proxy URL for all outbound requests, e.g. http://user:pass@proxy.company.com:8080 "
                              "(overrides config.json / HTTP_PROXY / HTTPS_PROXY)")
    args = parser.parse_args()

    config = load_config()
    proxy = resolve_proxy(args, config)
    if proxy:
        SESSION.proxies.update({"http": proxy, "https": proxy})
        print(f"Proxy enabled: {proxy}")

    output_dir = Path(args.output)
    for advisory_type in args.types.split(","):
        advisory_type = advisory_type.strip().lower()
        if advisory_type not in LIST_URL:
            print(f"Unknown advisory type '{advisory_type}', skipping (known: {', '.join(LIST_URL)})")
            continue

        type_dir = output_dir / advisory_type
        current_dir = type_dir / "current"
        new_dir = type_dir / "new"
        current_dir.mkdir(parents=True, exist_ok=True)
        reset_new_dir(new_dir)

        try:
            text = fetch_list(advisory_type)
        except requests.RequestException as exc:
            print(f"[{advisory_type}] failed to fetch list: {exc}")
            continue

        advisories = parse_list(text, advisory_type)
        print(f"[{advisory_type}] {len(advisories)} advisor(y/ies) in the upstream list")

        if args.days is not None:
            cutoff = date.today() - timedelta(days=args.days)
            before = len(advisories)
            advisories = [
                a for a in advisories
                if (parsed := parse_advisory_date(a["date"])) is None or parsed >= cutoff
            ]
            print(f"[{advisory_type}] {before - len(advisories)} advisor(y/ies) older than "
                  f"{args.days} day(s) filtered out ({len(advisories)} remaining)")

        new_count = 0
        for advisory in advisories:
            # ID-based dedup, same convention as cert_fr_fetch.py: presence of the file is the
            # watermark, no separate state file. A revised advisory (e.g. DSA-6455-2 replacing
            # DSA-6455-1) gets a different ID and is naturally treated as new, not a duplicate.
            dest = current_dir / f"{advisory['id']}.json"
            if dest.exists():
                continue
            payload = json.dumps(advisory, ensure_ascii=False, indent=2)
            dest.write_text(payload, encoding="utf-8")
            (new_dir / f"{advisory['id']}.json").write_text(payload, encoding="utf-8")
            new_count += 1

        print(f"[{advisory_type}] {new_count} new advisor(y/ies) this run")


if __name__ == "__main__":
    main()
