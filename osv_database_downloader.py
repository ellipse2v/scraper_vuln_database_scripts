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
import json
import argparse
from datetime import datetime

# list of ecosystem
CONST_URL_ECOSYSTEM = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"
CONST_URL_OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com/"
CONST_URL_GLOBAL_MODIFIED = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
list_ecosystem = []

# File to track last download timestamps
TIMESTAMP_TRACKER_FILE = "./download/timestamps.json"


def readOSVecosystem(response):
    # Create download directory if it doesn't exist
    os.makedirs("./download", exist_ok=True)
    
    with open("./download/osv_ecosystems.txt", "wb") as fichier:
        fichier.write(response.content)
        fichier.close()
        fichier = open("./download/osv_ecosystems.txt", "r")
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


def download_global_modified_file():
    """Download the global modified_id.csv file"""
    logging.info("Downloading global modified_id.csv file")
    
    try:
        response = requests.get(CONST_URL_GLOBAL_MODIFIED)
        response.raise_for_status()

        with open("./download/global_modified_id.csv", "wb") as fichier:
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
    """Download the modified_id.csv file for a specific ecosystem"""
    logging.info(f"Downloading modified_id.csv for ecosystem: {ecosystem}")
    
    # Construct URL for ecosystem-specific modified_id.csv
    url = f"https://storage.googleapis.com/osv-vulnerabilities/{urllib.parse.quote(ecosystem, encoding='utf-8')}/modified_id.csv"
    
    try:
        response = requests.get(url)
        response.raise_for_status()

        # Create ecosystem directory if it doesn't exist
        ecosystem_dir = f"./download/{ecosystem}"
        os.makedirs(ecosystem_dir, exist_ok=True)
        
        with open(f"{ecosystem_dir}/modified_id.csv", "wb") as fichier:
            fichier.write(response.content)
        
        logging.info(f"Successfully downloaded modified_id.csv for {ecosystem}")
        return True
        
    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to download modified_id.csv for {ecosystem}: {e}")
        return False
    except Exception as e:
        logging.warning(f"Exception while downloading modified_id.csv for {ecosystem}: {e}")
        return False


def downloadOSVdata(force_full=False):
    """Download OSV data with support for both full and incremental modes"""
    
    # Load timestamps to check if this is first run
    timestamps = load_timestamps()
    is_first_run = 'last_run' not in timestamps
    
    if list_ecosystem is not None and len(list_ecosystem) > 0:
        # Always download modified_id.csv files for tracking
        download_global_modified_file()
        
        for ecosystem in list_ecosystem:
            logging.info(f"Processing ecosystem: {ecosystem}")

            # Download ecosystem-specific modified_id.csv file
            download_ecosystem_modified_file(ecosystem)

            # Check if we should download full ZIP or just track changes
            should_download_full = is_first_run or force_full
            
            if should_download_full:
                url = f"{CONST_URL_OSV_BASE}{urllib.parse.quote(ecosystem, encoding='utf-8').replace(' ', '%20')}/all.zip"

                try:
                    response = requests.get(url)
                    response.raise_for_status()

                    with open("./download/"+ecosystem+".zip", "wb") as fichier:
                        fichier.write(response.content)
                    
                    logging.info(f"✓ Downloaded full {ecosystem} database")
                    
                except requests.exceptions.RequestException as e:
                    logging.error(f"✗ Download failed for {ecosystem}: {e}")
                except Exception as e:
                    logging.error(f"✗ Exception downloading {ecosystem}: {e}")
            else:
                logging.info(f"⊘ Skipping full download for {ecosystem} (incremental mode)")
                logging.info(f"  Use --force-full to download complete {ecosystem} database")

    else:
        logging.info("Google OSV mirroring is disabled. No ecosystem selected.")        

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='OSV Database Downloader with incremental update support')
    parser.add_argument('--force-full', action='store_true', 
                       help='Force full download of all data (ignore timestamps)')
    parser.add_argument('--incremental', action='store_true', 
                       help='Perform incremental update only (default behavior)')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Load previous timestamps
    timestamps = load_timestamps()
    current_run_time = datetime.now().isoformat()
    
    logging.info(f"Starting OSV database download - Run ID: {current_run_time}")
    logging.info(f"Force full download: {args.force_full}")
    
    response = requests.get(CONST_URL_ECOSYSTEM)
    if response.status_code == 200:
        readOSVecosystem(response)
        logging.info(f"Found {len(list_ecosystem)} ecosystems: {list_ecosystem[:5]}...")  # Show first 5
        
        # Store current run timestamp
        timestamps['last_run'] = current_run_time
        timestamps['ecosystems'] = list_ecosystem
        save_timestamps(timestamps)
        
        downloadOSVdata(force_full=args.force_full)
        
        logging.info("Download completed successfully")
    else:
        logging.error(f"Failed to download ecosystem list: {response.status_code}")
        exit(1)
	
if __name__ == "__main__":
    main()
