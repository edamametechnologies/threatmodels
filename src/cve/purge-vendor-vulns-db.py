import json
import re
from datetime import datetime
import hashlib

# Maintain the same age limit as in build-vendor-vulns-db.py
entry_year_limit = 3

verbosity_level = 1

def purge_old_entries(vendor_entry, vendor):
    # Purge old entries if any (with verbosity)
    current_year = datetime.now().year
    # Use a list comprehension to filter out old vulnerabilities
    original_count = len(vendor_entry["vulnerabilities"])
    vendor_entry["vulnerabilities"] = [
        vulnerability for vulnerability in vendor_entry["vulnerabilities"]
        if current_year - int(re.search(r"\d{4}", vulnerability["name"]).group()) <= entry_year_limit
    ]
    removed_count = original_count - len(vendor_entry["vulnerabilities"])
    if removed_count > 0:
        log(f"Removed {removed_count} old CVE(s) from vendor {vendor}.", 1)

def log(message, level=1):
    if verbosity_level >= level:
        print(message)

if __name__ == "__main__":
    existing_data_file = "./lanscan-vendor-vulns-db.json"
    try:
        with open(existing_data_file, "r") as file:
            existing_data = json.load(file)
            # Store the original signature
            original_signature = existing_data.get("signature", "")
    except FileNotFoundError:
        log("No existing database found.", 1)
        existing_data = {"date": datetime.now().strftime("%Y-%m-%d"), "vulnerabilities": []}
        original_signature = ""

    # Purge old entries for each vendor
    for vendor_entry in existing_data["vulnerabilities"]:
        vendor = vendor_entry["vendor"]
        purge_old_entries(vendor_entry, vendor)

    # Update the count of vulnerabilities for each vendor
    for vendor_entry in existing_data["vulnerabilities"]:
        vendor_entry["count"] = len(vendor_entry["vulnerabilities"])

    # Remove vendors with no remaining vulnerabilities
    existing_data["vulnerabilities"] = [
        vendor_entry for vendor_entry in existing_data["vulnerabilities"] if vendor_entry["count"] > 0
    ]

    # Sort the vulnerabilities by vendor
    existing_data["vulnerabilities"] = sorted(
        existing_data["vulnerabilities"], key=lambda x: x["vendor"].lower()
    )

    # Make a copy of the data without signature for calculating new signature
    existing_data_copy = existing_data.copy()
    existing_data_copy["signature"] = ""
    
    # Calculate new signature
    new_signature = hashlib.sha256(json.dumps(existing_data_copy, sort_keys=True).encode('utf-8')).hexdigest()
    
    # Only update the date if the content has changed
    if original_signature and original_signature == new_signature:
        log("Content unchanged - keeping original date.", 1)
    else:
        log("Content changed - updating date.", 1)
        existing_data["date"] = datetime.now().strftime("%B %dth %Y")
    
    # Always update the signature
    existing_data["signature"] = new_signature

    # Save the updated data back to the JSON file
    with open(existing_data_file, 'w') as file:
        json.dump(existing_data, file, indent=4, sort_keys=True)
        
    # Save signature to separate .sig file
    sig_file = existing_data_file.removesuffix(".json") + ".sig"
    with open(sig_file, 'w') as file:
        file.write(existing_data["signature"])

    log("Database purge completed.", 1)