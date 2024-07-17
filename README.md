# Endpoint Threat Models
This repo contains the threat models used by the EDAMAME Security application to compute its Security Score. 
The reference for defining macOS threats leverage NIST and CIS benchmarks as well as other sources.
The threats are categorized along 5 dimensions:
- Applications: includes application authorizations, signing, installed EPP/antivirus...
- Network: network related threats
- Credentials: threats linked to credentials
- System Integrity: includes installed MDM and other 3rd party admin / tampering threats
- System Services: threats linked to system services
The threats naming convention is as follows:
- The threat name is in the format shall describe the threat in a concise manner (and not its remediation)
- No '-' in the name
- Space is allowed in favor of the _ character
- No special characters
- No capital letters except for acronyms and the first letter of a commercial name
- E.g. 'Chrome not uptodate'