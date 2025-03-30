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
    today = datetime.datetime.now().strftime("%B %d %Y")
    
    blacklists_data = {
        "date": today,
        "blacklists": blacklists,
        "signature": ""  # Will be updated later
    }
    
    # Generate signature (hash of the blacklists content)
    blacklists_json = json.dumps(blacklists_data["blacklists"], sort_keys=True)
    blacklists_data["signature"] = hashlib.sha256(blacklists_json.encode()).hexdigest()
    
    return blacklists_data

def generate_signature_file(json_data, output_file):
    """Generate a separate .sig file with a base64 encoded signature."""
    # Create a signature from the full JSON content
    json_string = json.dumps(json_data, sort_keys=True)
    signature = hashlib.sha256(json_string.encode()).digest()
    
    # Base64 encode the signature
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    # Write the signature to a .sig file
    sig_filename = output_file.replace('.json', '.sig')
    with open(sig_filename, 'w') as f:
        f.write(signature_b64)
    
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
    
    # Create the final JSON structure
    blacklists_data = create_blacklist_json(blacklists)
    
    # Write to files
    output_file = "blacklists-db.json"
    with open(output_file, "w") as f:
        json.dump(blacklists_data, f, indent=2)
    
    # Generate the separate signature file
    generate_signature_file(blacklists_data, output_file)
    
    print(f"Created {output_file} with {len(blacklists)} blacklists")

if __name__ == "__main__":
    main()
