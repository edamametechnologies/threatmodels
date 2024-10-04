import json
import re
from datetime import datetime
import hashlib

verbosity_level = 1

def purge_old_entries(vendor_entry, vendor):
    # Purge old entries if any (with verbosity)
    current_year = datetime.now().year
    # Use a list comprehension to filter out old vulnerabilities
    original_count = len(vendor_entry["vulnerabilities"])
    vendor_entry["vulnerabilities"] = [
        vulnerability for vulnerability in vendor_entry["vulnerabilities"]
        if current_year - int(re.search(r"\d{4}", vulnerability["name"]).group()) <= 4
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
    except FileNotFoundError:
        log("No existing database found.", 1)
        existing_data = {"date": datetime.now().strftime("%Y-%m-%d"), "vulnerabilities": []}

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

    # Update the date and signature
    existing_data["date"] = datetime.now().strftime("%B %dth %Y")
    existing_data["signature"] = hashlib.sha256(json.dumps(existing_data).encode('utf-8')).hexdigest()

    # Save the updated data back to the JSON file
    with open(existing_data_file, 'w') as file:
        json.dump(existing_data, file, indent=4)

    log("Database purge completed.", 1)