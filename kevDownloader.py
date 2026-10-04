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
DOWNLOAD_DIR = "./download"

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EUVD_KEV_URL = "https://euvdservices.enisa.europa.eu/api/kev/dump"

CISA_KEV_FILE = f"{DOWNLOAD_DIR}/cisakev/known_exploited_vulnerabilities.json"
EUVD_KEV_FILE = f"{DOWNLOAD_DIR}/keveuvd/euvd_kev.json"
VULNCHECK_KEV_FILE = f"{DOWNLOAD_DIR}/vulncheck/vulncheck_kev.json"

DEFAULT_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
}


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
        **DEFAULT_HEADERS,
        "Authorization": f"Bearer {api_key}",
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

        # En cas d'erreur, on ne renvoie rien : sauvegarder un catalogue partiel
        # écraserait le fichier complet du passage précédent.
        except urllib.error.HTTPError as e:
            print(f"❌ Erreur HTTP sur VulnCheck ({e.code}): {e.reason}")
            return None
        except Exception as e:
            print(f"❌ Erreur réseau ou JSON sur VulnCheck: {e}")
            return None

    return all_data


def load_http_state(output_path):
    """Charge les en-têtes ETag/Last-Modified mémorisés lors du dernier téléchargement."""
    state_path = os.path.join(os.path.dirname(output_path), "http_state.json")
    if os.path.exists(state_path):
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_http_state(output_path, state):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    state_path = os.path.join(os.path.dirname(output_path), "http_state.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def fetch_json_if_changed(url, output_path):
    """Télécharge un dump JSON complet (CISA KEV, EUVD) avec une requête conditionnelle
    (If-None-Match / If-Modified-Since) : si le serveur répond 304, le fichier local est
    déjà à jour et rien n'est retéléchargé. Retourne (data, state) ou (None, None)."""
    print(f"🚀 Téléchargement depuis {url}...")
    headers = dict(DEFAULT_HEADERS)
    state = load_http_state(output_path) if os.path.exists(output_path) else {}
    if state.get("etag"):
        headers["If-None-Match"] = state["etag"]
    if state.get("last_modified"):
        headers["If-Modified-Since"] = state["last_modified"]
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
            new_state = {
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
            }
            return data, new_state
    except urllib.error.HTTPError as e:
        if e.code == 304:
            print(f"✅ Inchangé depuis le dernier téléchargement : {output_path}")
        else:
            print(f"❌ Erreur HTTP sur {url} ({e.code}): {e.reason}")
    except Exception as e:
        print(f"❌ Erreur lors du téléchargement de {url}: {e}")
    return None, None


def is_unchanged(data, output_path):
    """True si `data` est identique au fichier déjà présent (pas de réécriture inutile)."""
    if not os.path.exists(output_path):
        return False
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            return json.load(f) == data
    except (json.JSONDecodeError, IOError):
        return False


def save_json(data, output_path):
    """Sauvegarde les données dans un fichier JSON."""
    if data is None:
        return
    if is_unchanged(data, output_path):
        print(f"✅ Inchangé : {output_path}")
        return
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(
        f"✅ Enregistré : {output_path} ({len(data)} entrées)"
        if isinstance(data, list)
        else f"✅ Enregistré : {output_path}"
    )


def download_dump(url, output_path):
    data, state = fetch_json_if_changed(url, output_path)
    if data is not None:
        save_json(data, output_path)
        save_http_state(output_path, state)


def main():
    config = load_config()
    configure_proxy(config)

    # 1. CISA KEV (dump complet)
    download_dump(CISA_KEV_URL, CISA_KEV_FILE)

    # 2. EUVD ENISA KEV (dump complet)
    download_dump(EUVD_KEV_URL, EUVD_KEV_FILE)

    # 3. VulnCheck KEV (paginé, pas de requête conditionnelle possible)
    vulncheck_data = fetch_vulncheck_kev(resolve_vulncheck_api_key(config))
    if vulncheck_data:
        save_json(vulncheck_data, VULNCHECK_KEV_FILE)


if __name__ == "__main__":
    main()
