#!/usr/bin/env python3

import requests
import json
import datetime
import hashlib
import os
import base64

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
    
    # Generate signature (hash of the entire data with empty signature)
    json_string = json.dumps(blacklists_data, sort_keys=True)
    blacklists_data["signature"] = hashlib.sha256(json_string.encode()).hexdigest()
    
    return blacklists_data

def save_signature_file(signature, output_file):
    """Save the signature to a separate .sig file."""
    sig_filename = output_file.replace('.json', '.sig')
    with open(sig_filename, 'w') as f:
        f.write(signature)
    
    print(f"Created signature file: {sig_filename}")

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
    
    # Create the final JSON structure (with today's date initially)
    blacklists_data = create_blacklist_json(blacklists)
    new_signature = blacklists_data["signature"]
    
    # Check if content has changed by comparing signatures
    if original_signature and original_signature == new_signature and original_date:
        print("Content unchanged - keeping original date.")
        blacklists_data["date"] = original_date
    else:
        print("Content changed or new file - using today's date.")
    
    # Write to files
    with open(output_file, "w") as f:
        json.dump(blacklists_data, f, indent=2)
    
    # Save the signature to a separate .sig file
    save_signature_file(blacklists_data["signature"], output_file)
    
    print(f"Created {output_file} with {len(blacklists)} blacklists")

if __name__ == "__main__":
    main()
