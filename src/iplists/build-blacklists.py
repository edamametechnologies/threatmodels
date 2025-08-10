#!/usr/bin/env python3

import requests
import json
import datetime
import hashlib
import os
import base64

def get_ordinal_suffix(day):
    """Get the ordinal suffix for a day number (1st, 2nd, 3rd, 4th, etc.)"""
    if 10 <= day % 100 <= 20:
        suffix = 'th'
    else:
        suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
    return suffix

def download_blocklist(url):
    """Download the blocklist from the given URL."""
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response.text

def parse_ip_list(content):
    """Parse the IP list content, removing comments and empty lines."""
    ip_list = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        ip_list.append(line)
    return ip_list

def create_blacklist_json(blacklists):
    """Create the blacklists JSON structure."""
    today = datetime.datetime.now().strftime("%B %dth %Y")
    
    blacklists_data = {
        "date": today,
        "blacklists": blacklists,
        "signature": ""  # Will be updated later
    }
    
    return blacklists_data

def main():
    # Create directory if it doesn't exist
    os.makedirs("src/iplists", exist_ok=True)
    
    # Define the blacklists to download
    blacklist_sources = [
        {
            "name": "firehol_level1",
            "url": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
            "description": "A firewall blacklist for basic protection with minimum false positives"
        }
    ]
    
    # First, try to read existing file to get original date and signature
    output_file = "blacklists-db.json"
    original_date = None
    original_signature = None
    
    try:
        with open(output_file, "r") as f:
            existing_data = json.load(f)
            original_date = existing_data.get("date")
            original_signature = existing_data.get("signature")
    except (FileNotFoundError, json.JSONDecodeError):
        print("No existing blacklists file found or file is invalid.")
    
    blacklists = []
    
    # Process each blacklist source
    for source in blacklist_sources:
        print(f"Downloading {source['name']}...")
        content = download_blocklist(source["url"])
        ip_ranges = parse_ip_list(content)
        
        blacklist = {
            "name": source["name"],
            "description": source["description"],
            "last_updated": datetime.datetime.now().strftime("%Y-%m-%d"),
            "source_url": source["url"],
            "ip_ranges": ip_ranges
        }
        
        blacklists.append(blacklist)
        print(f"Processed {source['name']} with {len(ip_ranges)} IP ranges")
    
    # Create the final JSON structure (with a blank signature initially)
    blacklists_data = create_blacklist_json(blacklists)

    # ------------------------------------------------------------------
    # Compute hash of content with signature blanked to detect changes
    tmp_copy = blacklists_data.copy()
    tmp_copy["signature"] = ""
    new_content_hash = hashlib.sha256(json.dumps(tmp_copy, sort_keys=True).encode("utf-8")).hexdigest()

    # Decide whether to bump the date based on content change
    if not original_signature or original_signature != new_content_hash:
        now = datetime.datetime.now()
        day = now.day
        suffix = get_ordinal_suffix(day)
        blacklists_data["date"] = now.strftime(f"%B {day}{suffix} %Y")
    else:
        # Preserve previous date when content identical
        if original_date:
            blacklists_data["date"] = original_date

    # Compute FINAL signature including (potentially updated) date
    final_copy = blacklists_data.copy()
    final_copy["signature"] = ""
    blacklists_data["signature"] = hashlib.sha256(json.dumps(final_copy, sort_keys=True).encode("utf-8")).hexdigest()

    # Write updated JSON to disk (sorted keys for stability)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(blacklists_data, f, indent=2, sort_keys=True)

    # Write signature side-car .sig file
    sig_file = output_file.removesuffix(".json") + ".sig"
    with open(sig_file, "w", encoding="utf-8") as sf:
        sf.write(blacklists_data["signature"])

    print(f"Created {output_file} with {len(blacklists)} blacklists")

if __name__ == "__main__":
    main()
