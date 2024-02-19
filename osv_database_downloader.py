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

# list of ecosystem
CONST_URL_ECOSYSTEM = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"
CONST_URL_OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com/"
list_ecosystem = []


def readOSVecosystem(response):
    with open("./download/osv_ecosystems.txt", "wb") as fichier:
        fichier.write(response.content)
        fichier.close()
        fichier = open("./download/osv_ecosystems.txt", "r")
        lines = fichier.read().splitlines()
        fichier.close()

        list_ecosystem.extend(lines)


def downloadOSVdata():
    if list_ecosystem is not None and len(list_ecosystem) > 0:
        for ecosystem in list_ecosystem:
            logging.info(f"Updating datasource with Google OSV advisories for ecosystem {ecosystem}")

            url = f"{CONST_URL_OSV_BASE}{urllib.parse.quote(ecosystem, encoding='utf-8').replace(' ', '%20')}/all.zip"

            try:
                response = requests.get(url)
                response.raise_for_status()  # Raise exception for non-200 status codes

                with open("./download/"+ecosystem+".zip", "wb") as fichier:
                    fichier.write(response.content)

            except requests.exceptions.RequestException as e:
                logging.error(f"Download failed: {e}")
            except Exception as e:
                logging.error("Exception while executing request:", exc_info=e)

    else:
        logging.info("Google OSV mirroring is disabled. No ecosystem selected.")        

def main():
    response = requests.get(CONST_URL_ECOSYSTEM)
    if response.status_code == 200:
        readOSVecosystem(response)
        print(list_ecosystem)
        downloadOSVdata()
    else:
        print(f"Échec du téléchargement du fichier : {response.status_code}")
        exit()
	
if __name__ == "__main__":
    main()
