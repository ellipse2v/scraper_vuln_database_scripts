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

import json
import os
import urllib.error
import urllib.parse
import urllib.request

CONFIG_FILE = "./config.json"


def load_config():
    """Charge config.json s'il existe. Retourne {} sinon -- toutes les clés sont optionnelles."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"⚠️ Impossible de lire {CONFIG_FILE}: {e}")
    return {}


def resolve_vulncheck_api_key(config):
    """Résout la clé VulnCheck, dans l'ordre : variable d'environnement
    VULNCHECK_API_KEY > config.json 'vulncheck_api_key'."""
    if os.environ.get("VULNCHECK_API_KEY"):
        return os.environ["VULNCHECK_API_KEY"]
    return config.get("vulncheck_api_key") or None


def configure_proxy(config):
    """Applique la clé 'proxy' de config.json si présente. Sinon urllib continue
    d'utiliser les variables HTTP_PROXY/HTTPS_PROXY/NO_PROXY habituelles."""
    proxy = config.get("proxy")
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        urllib.request.install_opener(opener)


def fetch_vulncheck_kev(api_key):
    """Télécharge l'intégralité du KEV VulnCheck en parcourant la pagination."""
    if not api_key:
        print(
            "⚠️ VULNCHECK_API_KEY non configurée (env ou config.json). "
            "Ignoré pour VulnCheck."
        )
        return None

    base_url = "https://api.vulncheck.com/v3/index/vulncheck-kev"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }

    all_data = []
    cursor = None
    page = 1

    print("🚀 Début du téléchargement de VulnCheck KEV...")

    while True:
        # Initialisation de la pagination au premier tour, puis passage du curseur
        params = {"limit": "300"}
        if cursor:
            params["cursor"] = cursor
        else:
            params["start_cursor"] = "true"

        url = f"{base_url}?{urllib.parse.urlencode(params)}"
        print(f"   [VulnCheck] Téléchargement page {page}...")

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))

            items = payload.get("data", [])
            all_data.extend(items)

            # L'API VulnCheck renvoie le curseur sous `_meta.next_cursor`
            meta = payload.get("_meta", {})
            cursor = meta.get("next_cursor")

            if not cursor:
                print("✅ [VulnCheck] Toutes les pages ont été récupérées.")
                break

            page += 1

        except urllib.error.HTTPError as e:
            print(f"❌ Erreur HTTP sur VulnCheck ({e.code}): {e.reason}")
            break
        except Exception as e:
            print(f"❌ Erreur réseau ou JSON sur VulnCheck: {e}")
            break

    return all_data


def fetch_simple_json(url, headers):
    """Télécharge un fichier JSON simple (ex: EUVD ENISA)."""
    print(f"🚀 Téléchargement depuis {url}...")
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"❌ Erreur lors du téléchargement de {url}: {e}")
        return None


def save_json(data, output_path):
    """Sauvegarde les données dans un fichier JSON."""
    if data is None:
        return
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(
        f"✅ Enregistré : {output_path} ({len(data)} entrées)"
        if isinstance(data, list)
        else f"✅ Enregistré : {output_path}"
    )


def main():
    config = load_config()
    configure_proxy(config)

    # 1. Traitement de VulnCheck (paginé)
    vulncheck_data = fetch_vulncheck_kev(resolve_vulncheck_api_key(config))
    if vulncheck_data:
        save_json(
            vulncheck_data, "output/vulncheck/vulncheck_kev.json"
        )

    # 2. Traitement d'EUVD ENISA (dump simple)
    euvd_headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    euvd_data = fetch_simple_json(
        "https://euvdservices.enisa.europa.eu/api/kev/dump",
        euvd_headers,
    )
    if euvd_data:
        save_json(euvd_data, "output/euvd/euvd_kev.json")


if __name__ == "__main__":
    main()