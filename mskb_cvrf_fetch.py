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
# Above this share of current/ missing from the listing, the listing is assumed truncated
# (API glitch) rather than the documents withdrawn, and nothing is moved to removed/.
MAX_REMOVED_RATIO = 0.05

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


def load_manifest(path: Path) -> dict:
    """{document ID: CurrentReleaseDate} of the copy in current/, as listed by MSRC when it was
    downloaded. A missing or unreadable manifest makes every document look changed."""
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def move_removed(current_dir: Path, removed_dir: Path, listed_ids: set[str], manifest: dict) -> None:
    """Moves documents no longer listed by MSRC from current/ to removed/ (kept, never deleted)."""
    files = sorted(current_dir.glob("cvrf_*.xml"))
    gone = [f for f in files if f.stem[len("cvrf_"):] not in listed_ids]
    if len(gone) > MAX_REMOVED_RATIO * len(files):
        print(f"WARNING: {len(gone)}/{len(files)} document(s) missing from the MSRC listing "
              f"(more than {MAX_REMOVED_RATIO:.0%}), listing probably incomplete: nothing moved "
              f"to removed/")
        return
    for f in gone:
        doc_id = f.stem[len("cvrf_"):]
        removed_dir.mkdir(parents=True, exist_ok=True)
        f.replace(removed_dir / f.name)
        manifest.pop(doc_id, None)
        print(f"[{doc_id}] no longer listed by MSRC, moved to {removed_dir}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="download/mskb", help="Output directory")
    parser.add_argument("--ids",
                         help="Comma-separated document IDs to fetch, e.g. 2018-Jan,2023-May "
                              "(default: every document listed by MSRC)")
    parser.add_argument("--force-full", action="store_true",
                         help="Re-download every document, even those already in current/ "
                              "(default: only the new ones and those whose CurrentReleaseDate "
                              "changed)")
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
    removed_dir = output_dir / "removed"
    current_dir.mkdir(parents=True, exist_ok=True)
    reset_new_dir(new_dir)
    manifest_path = output_dir / "manifest.json"
    manifest = load_manifest(manifest_path)

    try:
        updates = fetch_updates()
    except requests.RequestException as exc:
        print(f"Failed to list MSRC CVRF documents: {exc}")
        return
    # Only a complete, non-empty listing can tell that a document was withdrawn.
    if updates and not args.ids:
        move_removed(current_dir, removed_dir, {u["ID"] for u in updates}, manifest)
    if args.ids:
        wanted = {i.strip() for i in args.ids.split(",") if i.strip()}
        updates = [u for u in updates if u.get("ID") in wanted]
        missing = wanted - {u["ID"] for u in updates}
        if missing:
            print(f"Unknown document ID(s), skipped: {', '.join(sorted(missing))}")
    print(f"{len(updates)} CVRF document(s) listed")

    new_count = updated_count = failed_count = 0
    for update in updates:
        doc_id = update["ID"]
        dest = current_dir / f"cvrf_{doc_id}.xml"
        release_date = update.get("CurrentReleaseDate")
        # MSRC revises documents in place (same ID): a new CurrentReleaseDate means new content.
        is_update = dest.exists()
        if is_update and manifest.get(doc_id) == release_date and not args.force_full:
            continue
        try:
            content = fetch_cvrf_xml(doc_id)
        except (requests.RequestException, ValueError) as exc:
            print(f"[{doc_id}] failed: {exc}")
            failed_count += 1
            continue
        dest.write_bytes(content)
        (new_dir / dest.name).write_bytes(content)
        manifest[doc_id] = release_date
        if is_update:
            updated_count += 1
            print(f"[{doc_id}] updated ({len(content)} bytes, release date {release_date})")
        else:
            new_count += 1
            print(f"[{doc_id}] saved ({len(content)} bytes)")

    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(f"{new_count} new and {updated_count} updated document(s) this run, {failed_count} failed")


if __name__ == "__main__":
    main()
