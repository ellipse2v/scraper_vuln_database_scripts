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
"""Downloads the Microsoft Security Response Center (MSRC) CVRF documents, one XML file per
monthly release (cvrf_2018-Jan.xml, ...), for Dependency-Track's MSKB offline mirror (KB -> CVE).

The MSRC API serves the same document as JSON or XML depending on the Accept header: a JSON
answer saved as .xml is what DT rejects with "Content is not allowed in prolog". XML is always
requested explicitly here, and every document is checked to be a CVRF XML document before it is
written.
"""

import argparse
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{id}"

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
    consulting the usual HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables on its own."""
    if args.proxy:
        return args.proxy
    return config.get("proxy")


def fetch_updates() -> list[dict]:
    """Lists every CVRF document (ID, CurrentReleaseDate, ...) published by MSRC."""
    resp = SESSION.get(UPDATES_URL, headers={"Accept": "application/json"}, timeout=60)
    resp.raise_for_status()
    return resp.json().get("value", [])


def fetch_cvrf_xml(doc_id: str) -> bytes:
    """Downloads one CVRF document as XML. Raises ValueError if the answer isn't CVRF XML."""
    resp = SESSION.get(CVRF_URL.format(id=doc_id), headers={"Accept": "application/xml"}, timeout=120)
    resp.raise_for_status()
    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as exc:
        raise ValueError(f"not an XML document ({exc}), starts with {resp.content[:40]!r}") from exc
    if not root.tag.endswith("cvrfdoc"):
        raise ValueError(f"unexpected XML root element {root.tag}")
    return resp.content


def reset_new_dir(new_dir: Path) -> None:
    """Empty `new_dir` so it only ever holds this run's newly fetched documents."""
    if new_dir.exists():
        for f in new_dir.iterdir():
            f.unlink()
    else:
        new_dir.mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="download/mskb", help="Output directory")
    parser.add_argument("--ids",
                         help="Comma-separated document IDs to fetch, e.g. 2018-Jan,2023-May "
                              "(default: every document listed by MSRC)")
    parser.add_argument("--force-full", action="store_true",
                         help="Re-download every document, even those already in current/ "
                              "(default: only download the ones not there yet)")
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
    current_dir = output_dir / "current"
    new_dir = output_dir / "new"
    current_dir.mkdir(parents=True, exist_ok=True)
    reset_new_dir(new_dir)

    try:
        updates = fetch_updates()
    except requests.RequestException as exc:
        print(f"Failed to list MSRC CVRF documents: {exc}")
        return
    if args.ids:
        wanted = {i.strip() for i in args.ids.split(",") if i.strip()}
        updates = [u for u in updates if u.get("ID") in wanted]
        missing = wanted - {u["ID"] for u in updates}
        if missing:
            print(f"Unknown document ID(s), skipped: {', '.join(sorted(missing))}")
    print(f"{len(updates)} CVRF document(s) listed")

    new_count = failed_count = 0
    for update in updates:
        doc_id = update["ID"]
        dest = current_dir / f"cvrf_{doc_id}.xml"
        # Same convention as cert_fr_fetch.py: presence of the file is the watermark.
        if dest.exists() and not args.force_full:
            continue
        try:
            content = fetch_cvrf_xml(doc_id)
        except (requests.RequestException, ValueError) as exc:
            print(f"[{doc_id}] failed: {exc}")
            failed_count += 1
            continue
        dest.write_bytes(content)
        (new_dir / dest.name).write_bytes(content)
        print(f"[{doc_id}] saved ({len(content)} bytes)")
        new_count += 1

    print(f"{new_count} document(s) downloaded this run, {failed_count} failed")


if __name__ == "__main__":
    main()
