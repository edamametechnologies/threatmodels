import aiohttp
import asyncio
from bs4 import BeautifulSoup
import json
import re
from datetime import datetime
import hashlib

verbosity_level = 1

def get_ordinal_suffix(day):
    """Get the ordinal suffix for a day number (1st, 2nd, 3rd, 4th, etc.)"""
    if 10 <= day % 100 <= 20:
        suffix = 'th'
    else:
        suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
    return suffix

def clean_vendor_name(vendor_name):
    # Pattern to match common corporate designations (case-insensitive)
    pattern = r'\b(Ltd|Corp|Corporation|Incorporated|Inc|GmbH|S\.A\.|NV|LLC|SaS|SAS|AG|BV|Pvt|Pte|Pty|Sdn|Bhd|Ltda|S\.r\.l|Srl|SpA|SpZoo|LLP|PLC|Co|Co\.|Co,|Co-|Co:|Co;|Co\||Co\.)\b'

    # Remove the matched patterns/designations
    cleaned_name = re.sub(pattern, '', vendor_name, flags=re.IGNORECASE)

    # Only keep alpha characters, digits, and spaces
    cleaned_name = re.sub(r'[^a-zA-Z0-9\s]', '', cleaned_name)

    # Remove any extra spaces left after removal
    cleaned_name = re.sub(r'\s+', ' ', cleaned_name).strip()

    # Only keep the first 2 words
    cleaned_name = ' '.join(cleaned_name.split()[:2])

    return cleaned_name

async def load_vendor_names(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            text = await response.text()
            vendors = []
            for line in text.splitlines():
                if line.strip() and not line.startswith('#'):
                    parts = line.split()
                    vendor_name = ' '.join(parts[2:])
                    vendors.append(clean_vendor_name(vendor_name))

            # Remove duplicates
            vendors = list(set(vendors))
            log("Loaded vendor names.", 1)
            return vendors

async def purge_old_entries(vendor_entry, data_semaphore, vendor):
    async with data_semaphore:
        # Purge old entries if any (with verbosity)
        current_year = datetime.now().year
        for vulnerability in vendor_entry["vulnerabilities"]:
            if current_year - int(re.search(r"\d{4}", vulnerability["name"]).group()) > 4:
                log(f"Removing old CVE {vulnerability['name']} from vendor {vendor}.", 1)
                vendor_entry["vulnerabilities"].remove(vulnerability)


async def fetch_and_update_cve_data(semaphore, data_semaphore, session, vendor, existing_data):
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={vendor}"
    attempt = 0
    max_retries = 10
    while attempt < max_retries:
        try:
            async with semaphore:
                log(f"Fetching data for vendor {vendor} (url {url})", 2)

                vendor_entry = next((item for item in existing_data["vulnerabilities"] if item["vendor"] == vendor), None)
                if not vendor_entry:
                    log(f"Vendor {vendor} not found in the database.", 1)
                else:
                    await purge_old_entries(vendor_entry, data_semaphore, vendor)

                async with session.get(url) as response:
                    if response.status == 200:
                        soup = BeautifulSoup(await response.text(), 'html.parser')
                        table = soup.find('div', {'id': 'TableWithRules'})
                        rows = table.find_all('tr') if table else []
                        log(f"Checking vendor {vendor}... Found {len(rows) - 1} rows.", 1)
                        for row in rows[1:]:
                            cols = row.find_all('td')
                            if len(cols) == 2:
                                cve_name, cve_description = cols[0].text.strip(), cols[1].text.strip()
                                # Make sure the cve description will be encodable in a JSON string by removing illegal characters like quotes
                                cve_description = cve_description.replace('"', "'")
                                # Check if the description contains the vendor name
                                if re.search(rf"\b{vendor}\b", cve_description, re.IGNORECASE):
                                    await update_cve_data(data_semaphore, cve_name, cve_description, vendor, existing_data)
                                else:
                                    log(f"Skipping CVE {cve_name} for vendor {vendor_entry} because it does not mention the vendor.", 2)
                                    log(f"Description: {cve_description}", 3)
                    else:
                        log(f"Received bad response status: {response.status}", 2)
                        raise aiohttp.ClientError(f"Bad response: {response.status}")
                break
        except Exception as e:
            log(f"Error fetching data for vendor {vendor}: {e}. Retrying...", 2)
            attempt += 1
            await asyncio.sleep(2)
    if attempt == max_retries and verbosity_level >= 1:
        print(f"Failed to fetch data for vendor {vendor} after {max_retries} retries.")

async def update_cve_data(data_semaphore, cve_name, cve_description, vendor, existing_data):
    async with data_semaphore:
        current_year = datetime.now().year
        cve_year = int(re.search(r"\d{4}", cve_name).group())
        if current_year - cve_year > 4:
            log(f"Skipping CVE {cve_name} because it is older than 4 years.", 2)
            return  # Skip adding if CVE is older than 4 years

        vendor_entry = next((item for item in existing_data["vulnerabilities"] if item["vendor"] == vendor), None)
        if not vendor_entry:
            log(f"Adding vendor {vendor} to the database.", 2)
            vendor_entry = {
                "vendor": vendor,
                "vulnerabilities": []
            }
            # Append in the database
            existing_data["vulnerabilities"].append(vendor_entry)

        if not any(cve["name"] == cve_name for cve in vendor_entry["vulnerabilities"]):
            log(f"Adding CVE {cve_name} to vendor {vendor}.", 2)
            vendor_entry["vulnerabilities"].append({
                "name": cve_name,
                "description": cve_description
            })
        else:
            log(f"Skipping CVE {cve_name} for vendor {vendor} because it already exists.", 1)

def log(message, level=1):
    if verbosity_level >= level:
        print(message)

async def main(existing_data):
    ouidb_url = "https://www.wireshark.org/download/automated/data/manuf"
    vendors = await load_vendor_names(ouidb_url)

    semaphore = asyncio.Semaphore(20)  # Control concurrency for network requests
    data_semaphore = asyncio.Semaphore(1)  # Control concurrency for data access
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_and_update_cve_data(semaphore, data_semaphore, session, vendor, existing_data) for vendor in vendors]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    existing_data_file = "./lanscan-vendor-vulns-db.json"
    try:
        with open(existing_data_file, "r") as file:
            existing_data = json.load(file)
            # Store the original signature
            original_signature = existing_data.get("signature", "")
    except FileNotFoundError:
        log("No existing database found. Creating a new one.", 1)
        existing_data = {"date": datetime.now().strftime("%Y-%m-%d"), "vulnerabilities": []}
        original_signature = ""

    asyncio.run(main(existing_data))

    # Add a counter for the number of vulnerabilities for each port
    for port in existing_data["vulnerabilities"]:
        port["count"] = len(port["vulnerabilities"])

    # Sort the vulnerabilities by vendor
    existing_data["vulnerabilities"] = sorted(existing_data["vulnerabilities"], key=lambda x: x["vendor"].lower())

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
        now = datetime.now()
        day = now.day
        suffix = get_ordinal_suffix(day)
        existing_data["date"] = now.strftime(f"%B {day}{suffix} %Y")
    
    # Always update the signature
    existing_data["signature"] = new_signature

    with open(existing_data_file, 'w') as file:
        json.dump(existing_data, file, indent=4, sort_keys=True)
        
    # Save signature to separate .sig file
    sig_file = existing_data_file.removesuffix(".json") + ".sig"
    with open(sig_file, 'w') as file:
        file.write(existing_data["signature"])

    log("Database update completed.", 1)
