import aiohttp
import asyncio
from bs4 import BeautifulSoup
import json
import re
from datetime import datetime
import hashlib

verbosity_level = 1

async def load_port_descriptions(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            text = await response.text()
            port_services = {}
            for line in text.splitlines():
                if line.strip() and not line.startswith('#'):
                    parts = line.split()
                    service_name = parts[0]
                    port_protocol = parts[1]
                    port, protocol = port_protocol.split('/')
                    if protocol.lower() == 'tcp' and service_name.lower() != 'unknown':
                        description = line.split('#', 1)[1].strip() if '#' in line else ''
                        port_services[port] = {"name": service_name, "description": description}
            log("Loaded port descriptions.", 1)
            return port_services

async def purge_old_entries(port_entry, data_semaphore, tcp_port):
    async with data_semaphore:
        # Purge old entries if any (with verbosity)
        current_year = datetime.now().year
        for vulnerability in port_entry["vulnerabilities"]:
            if current_year - int(re.search(r"\d{4}", vulnerability["name"]).group()) > 5:
                log(f"Removing old CVE {vulnerability['name']} from port {tcp_port}.", 1)
                port_entry["vulnerabilities"].remove(vulnerability)


async def fetch_and_update_cve_data(semaphore, data_semaphore, session, tcp_port, port_descriptions, existing_data, port_lookup):
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=tcp+{tcp_port}"
    attempt = 0
    max_retries = 10
    while attempt < max_retries:
        try:
            async with semaphore:
                log(f"Fetching data for port {tcp_port} (url {url})", 2)

                # Use the port_lookup dictionary for faster lookups
                port_entry = port_lookup.get(tcp_port)
                if not port_entry:
                    log(f"Port {tcp_port} not found in the database.", 1)
                else:
                    await purge_old_entries(port_entry, data_semaphore, tcp_port)

                async with session.get(url) as response:
                    if response.status == 200:
                        soup = BeautifulSoup(await response.text(), 'html.parser')
                        table = soup.find('div', {'id': 'TableWithRules'})
                        rows = table.find_all('tr') if table else []
                        log(f"Checking port {tcp_port}... Found {len(rows) - 1} rows.", 1)
                        for row in rows[1:]:
                            cols = row.find_all('td')
                            if len(cols) == 2:
                                cve_name, cve_description = cols[0].text.strip(), cols[1].text.strip()
                                # Check if the description contains the port number (port xxxx or tcp/xxxx)
                                if re.search(rf"\b(port |tcp\/){tcp_port}\b", cve_description, re.IGNORECASE):
                                    # Make sure the cve description will be encodable in a JSON string by removing illegal characters like quotes
                                    cve_description = cve_description.replace('"', "'")
                                    await update_cve_data(data_semaphore, cve_name, cve_description, tcp_port, port_descriptions, existing_data, port_lookup)
                                else:
                                    log(f"Skipping CVE {cve_name} for port {tcp_port} because it does not mention the port number.", 2)
                                    log(f"Description: {cve_description}", 3)
                    else:
                        log(f"Received bad response status: {response.status}", 2)
                        raise aiohttp.ClientError(f"Bad response: {response.status}")
                break
        except Exception as e:
            log(f"Error fetching data for port {tcp_port}: {e}. Retrying...", 2)
            attempt += 1
            await asyncio.sleep(2)
    if attempt == max_retries and verbosity_level >= 1:
        print(f"Failed to fetch data for port {tcp_port} after {max_retries} retries.")

async def update_cve_data(data_semaphore, cve_name, cve_description, tcp_port, port_descriptions, existing_data, port_lookup):
    async with data_semaphore:
        current_year = datetime.now().year
        cve_year = int(re.search(r"\d{4}", cve_name).group())
        if current_year - cve_year > 5:
            log(f"Skipping CVE {cve_name} because it is older than 5 years.", 2)
            return  # Skip adding if CVE is older than 5 years

        port_desc = port_descriptions.get(tcp_port, {"name": "", "description": ""})

        # Use the port_lookup dictionary for faster lookups
        port_entry = port_lookup.get(tcp_port)
        if not port_entry:
            log(f"Adding port {tcp_port} to the database.", 2)
            port_entry = {
                "port": tcp_port,
                "name": port_desc["name"],
                "description": port_desc["description"],
                "vulnerabilities": []
            }
            # Append in the database
            existing_data["vulnerabilities"].append(port_entry)
            # Add to the lookup dictionary
            port_lookup[tcp_port] = port_entry

        if not any(cve["name"] == cve_name for cve in port_entry["vulnerabilities"]):
            log(f"Adding CVE {cve_name} to port {tcp_port}.", 2)
            port_entry["vulnerabilities"].append({
                "name": cve_name,
                "description": cve_description
            })
        else:
            log(f"Skipping CVE {cve_name} for port {tcp_port} because it already exists.", 1)

def log(message, level=1):
    if verbosity_level >= level:
        print(message)

async def main(existing_data):
    nmap_services_url = "https://svn.nmap.org/nmap/nmap-services"
    port_descriptions = await load_port_descriptions(nmap_services_url)
    start_port, end_port = 0, 65535
    
    # Increase the concurrency - this is the key trick to speed up the script
    # Allowing more concurrent connections will significantly speed up the process
    semaphore = asyncio.Semaphore(100)  # Increased from 20 to 100
    
    # Use TCP connection pooling for better performance
    conn = aiohttp.TCPConnector(limit=100, limit_per_host=20)
    
    data_semaphore = asyncio.Semaphore(1)  # Control concurrency for data access
    
    # Create a lookup dictionary for faster port entry access
    port_lookup = {item["port"]: item for item in existing_data["vulnerabilities"]}
    
    # Use a high-performance ClientSession with optimized settings
    timeout = aiohttp.ClientTimeout(total=60, connect=10, sock_connect=10, sock_read=30)
    
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        # Group tasks in chunks to prevent overwhelming the event loop
        chunk_size = 1000
        all_tasks = []
        
        for start in range(start_port, end_port + 1, chunk_size):
            end = min(start + chunk_size - 1, end_port)
            chunk_tasks = [
                fetch_and_update_cve_data(semaphore, data_semaphore, session, port, port_descriptions, existing_data, port_lookup) 
                for port in range(start, end + 1)
            ]
            # Process each chunk of tasks
            await asyncio.gather(*chunk_tasks)
            log(f"Completed chunk {start}-{end}", 1)


if __name__ == "__main__":
    existing_data_file = "./lanscan-port-vulns-db.json"
    try:
        with open(existing_data_file, "r") as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        log("No existing database found. Creating a new one.", 1)
        existing_data = {"date": datetime.now().strftime("%Y-%m-%d"), "vulnerabilities": []}

    asyncio.run(main(existing_data))

    # Add a counter for the number of vulnerabilities for each port
    for port in existing_data["vulnerabilities"]:
        port["count"] = len(port["vulnerabilities"])

    # Check if the description contains HTTP or HTTPS and set the protocol accordingly
    for port in existing_data["vulnerabilities"]:
        if re.search(r"\bhttp\b", port["description"], re.IGNORECASE):
            port["protocol"] = "http"
        elif re.search(r"\bhttps\b", port["description"], re.IGNORECASE):
            port["protocol"] = "https"
        else:
            port["protocol"] = "tcp"

    # Sort the vulnerabilities by port number
    existing_data["vulnerabilities"].sort(key=lambda x: int(x['port']))

    # Update the date and signature
    existing_data["date"] = datetime.now().strftime("%B %dth %Y")
    existing_data["signature"] = hashlib.sha256(json.dumps(existing_data).encode('utf-8')).hexdigest()

    with open(existing_data_file, 'w') as file:
        json.dump(existing_data, file, indent=4)

    log("Database update completed.", 1)
