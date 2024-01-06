import aiohttp
import asyncio
from bs4 import BeautifulSoup
import json
import re

async def contains_port(description, port):
    pattern = fr"\b(port {port}\b|tcp/{port}\b)"
    return re.search(pattern, description, re.IGNORECASE)

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
                        description = ''
                        if '#' in line:
                            description = line.split('#')[-1].strip()

                        port_services[port] = {
                            "name": service_name,
                            "description": description
                        }
            return port_services

async def fetch_cve_data(semaphore, session, tcp_port, port_descriptions, max_retries=10):
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=tcp+{tcp_port}"

    attempt = 0
    while attempt < max_retries:
        try:
            async with semaphore:  # Acquire semaphore
                async with session.get(url) as response:
                    if response.status == 200:
                        cve_data = []
                        soup = BeautifulSoup(await response.text(), 'html.parser')
                        table = soup.find('div', {'id': 'TableWithRules'})
                        rows = table.find_all('tr') if table else []

                        print(f"Found {len(rows)} rows for port {tcp_port}")

                        for row in rows[1:]:
                            cols = row.find_all('td')
                            if len(cols) == 2:
                                cve_name = cols[0].text.strip()
                                cve_year = int(cve_name.split('-')[1])
                                cve_description = cols[1].text.strip()

                                if await contains_port(cve_description, tcp_port) and cve_year >= 2013:
                                    port_desc = port_descriptions.get(str(tcp_port))
                                    if port_desc:
                                        cve_data.append((cve_name, cve_description, str(tcp_port), port_desc["name"], port_desc["description"]))
                                    else:
                                        cve_data.append((cve_name, cve_description, str(tcp_port), "", ""))
                                    print(f"Found CVE {cve_name} for port {tcp_port}")

                        return cve_data
                    else:
                        raise aiohttp.ClientError(f"Bad response: {response.status}")

        except Exception as e:
            print(f"Error fetching data for port {tcp_port}: {e}. Retrying...")
            attempt += 1
            await asyncio.sleep(2)  # Wait for 2 seconds before retrying

    print(f"Failed to fetch data for port {tcp_port} after {max_retries} retries.")
    return []

def create_json_from_cve_list(cve_list):
    port_data = {}

    for cve in cve_list:
        cve_name, cve_description, tcp_port, port_name, port_description = cve

        if tcp_port not in port_data:
            port_data[tcp_port] = {
                "port": tcp_port,
                "name": port_name,
                "description": port_description,
                "vulnerabilities": []
            }

        port_data[tcp_port]["vulnerabilities"].append({
            "name": cve_name,
            "description": cve_description,
        })

    return list(port_data.values())

def save_to_file(data, filename):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

async def main():
    nmap_services_url = "https://svn.nmap.org/nmap/nmap-services"
    port_descriptions = await load_port_descriptions(nmap_services_url)

    start_port = 0
    end_port = 65536  # Total number of ports
    save_interval = 1000  # Number of ports per file
    suffix_counter = 0   # Suffix for filename

    semaphore = asyncio.Semaphore(20)  # Limit concurrent requests to 20

    async with aiohttp.ClientSession() as session:
        for current_port in range(start_port, end_port, save_interval):
            tasks = []
            for port in range(current_port, min(current_port + save_interval, end_port)):
                task = asyncio.create_task(fetch_cve_data(semaphore, session, port, port_descriptions))
                tasks.append(task)

            results = await asyncio.gather(*tasks)
            # Flatten the list of lists
            flat_results = [item for sublist in results for item in sublist]

            if flat_results:
                json_data = create_json_from_cve_list(flat_results)
                filename = f"port_vulns_db_{suffix_counter}.json"
                save_to_file(json_data, filename)
                print(f"Processed ports up to {current_port + save_interval} and saved to {filename}")
                suffix_counter += 1  # Increment filename suffix

# Run the main coroutine
if __name__ == "__main__":
    asyncio.run(main())