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

"""Fetches all CERT-FR bulletins (avis/alerte) and saves them as JSON."""

import argparse
import json
import os
import re
import time
from pathlib import Path

import requests

BASE_URL = "https://www.cert.ssi.gouv.fr"
REF_RE = re.compile(r"/(avis|alerte)/(CERTFR-\d{4}-(?:AVI|ALE)-\d+)/")

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


def list_references(bulletin_type: str, delay: float) -> list[str]:
    """Walks the listing pages and returns every reference found."""
    references = []
    page = 1
    while True:
        url = f"{BASE_URL}/{bulletin_type}/" if page == 1 else f"{BASE_URL}/{bulletin_type}/page/{page}/"
        resp = SESSION.get(url, timeout=30)
        if resp.status_code == 404:
            break
        resp.raise_for_status()
        found = sorted(set(m.group(2) for m in REF_RE.finditer(resp.text) if m.group(1) == bulletin_type))
        if not found:
            break
        references.extend(found)
        print(f"[{bulletin_type}] page {page}: {len(found)} reference(s)")
        page += 1
        time.sleep(delay)
    return sorted(set(references))


def fetch_bulletin(bulletin_type: str, reference: str) -> dict:
    url = f"{BASE_URL}/{bulletin_type}/{reference}/json/"
    resp = SESSION.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def reset_new_dir(new_dir: Path) -> None:
    """Empty `new_dir` so it only ever holds this run's newly fetched bulletins."""
    if new_dir.exists():
        for f in new_dir.iterdir():
            f.unlink()
    else:
        new_dir.mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="bulletins", help="Output directory")
    parser.add_argument("--types", default="avis,alerte", help="Types to fetch (avis,alerte)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests (s)")
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
    for bulletin_type in args.types.split(","):
        bulletin_type = bulletin_type.strip()
        type_dir = output_dir / bulletin_type
        current_dir = type_dir / "current"
        new_dir = type_dir / "new"
        current_dir.mkdir(parents=True, exist_ok=True)
        reset_new_dir(new_dir)

        references = list_references(bulletin_type, args.delay)
        print(f"[{bulletin_type}] {len(references)} bulletin(s) found")

        new_count = 0
        for reference in references:
            dest = current_dir / f"{reference}.json"
            if dest.exists():
                continue
            try:
                data = fetch_bulletin(bulletin_type, reference)
            except requests.RequestException as exc:
                print(f"[{bulletin_type}] failed {reference}: {exc}")
                continue
            payload = json.dumps(data, ensure_ascii=False, indent=2)
            dest.write_text(payload, encoding="utf-8")
            (new_dir / f"{reference}.json").write_text(payload, encoding="utf-8")
            new_count += 1
            print(f"[{bulletin_type}] saved {reference}")
            time.sleep(args.delay)

        print(f"[{bulletin_type}] {new_count} new bulletin(s) this run")


if __name__ == "__main__":
    main()
