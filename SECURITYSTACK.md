# Security Software Detection

EDAMAME Security's threat models include automated detection of common security software to ensure endpoints have adequate protection. This document lists the supported Endpoint Protection Platforms (EPP) and Password Managers recognized by the detection scripts.

## Table of Contents
- [Endpoint Protection Platforms (EPP/EDR/Antivirus)](#endpoint-protection-platforms-eppedr)
  - [macOS](#macos-epp)
  - [Windows](#windows-epp)
- [Password Managers](#password-managers)
  - [macOS](#macos-password-managers)
  - [Windows](#windows-password-managers)

---

## Endpoint Protection Platforms (EPP/EDR)

### macOS EPP

EDAMAME detects the following EPP/EDR/Antivirus solutions on macOS:

| **Vendor** | **Product** | **Detection Method** |
|------------|-------------|---------------------|
| **Bitdefender** | Bitdefender Endpoint Security | Process: `BDLDaemon` |
| **Malwarebytes** | Malwarebytes for Mac | Process: `RTProtectionDaemon` |
| **SentinelOne** | SentinelOne Agent | CLI: `sentinelctl version` |
| **CrowdStrike** | Falcon | LaunchDaemon plist, System Extension, or CLI: `falconctl` |
| **VMware** | Carbon Black Cloud / EDR | LaunchDaemon plist or System Extension |
| **Microsoft** | Defender for Endpoint | CLI: `mdatp health` or Process: `wdavdaemon` |
| **Sophos** | Intercept X / Endpoint | Process: `SophosScanD` or bundle identifier |
| **Symantec** | Endpoint Protection | Process: `SymDaemon` |
| **Trend Micro** | Apex One | Process: `iCoreService` or System Extension |
| **Palo Alto Networks** | Cortex XDR (Traps) | Binary: `cytool`, Process: `pmd`, or LaunchDaemon plist |
| **Jamf** | Jamf Protect | Process: `JamfProtectAgent` or CLI: `protectctl` |
| **BlackBerry** | Cylance Protect | LaunchDaemon plist or Process: `CylanceSvc` |
| **ESET** | Endpoint Security | Process: `esets_daemon` |
| **Apple** | XProtect Remediator | CLI: `xprotect status` or Process: `xprotect`/`XProtect` (fallback for older macOS) |

**Detection Script**: `threat model macOS/no EPP/implementation.sh`

---

### Windows EPP

EDAMAME detects the following EPP/EDR/Antivirus solutions on Windows:

| **Vendor** | **Product** | **Detection Method** |
|------------|-------------|---------------------|
| **Microsoft** | Defender Antivirus | Windows Security Center or `Get-MpComputerStatus` |
| **Microsoft** | Defender for Endpoint | Service: `WinDefend` or Process: `MsMpEng` |
| **SentinelOne** | SentinelOne Agent | Service/Process: `SentinelAgent` or Install directory |
| **CrowdStrike** | Falcon | Service/Process: `CSFalconService` or Install directory |
| **Sophos** | Endpoint Protection | Services: `SEDService`, `SSPService` |
| **Symantec** | Endpoint Protection | Services: `SepMasterService`, `sepWscSvc` |
| **Trend Micro** | Apex One | Services: `TMBMSRV`, `TmPfw`, `ntrtscan` or Process: `ntrtscan` |
| **Palo Alto Networks** | Cortex XDR / Traps | Services: `cyserver`, `CyveraService` or Install directory |
| **BlackBerry** | Cylance Protect | Service: `CylanceSvc` |
| **ESET** | Endpoint Security | Service: `ekrn` or Process: `ekrn` |
| **Trellix / McAfee** | Endpoint Security | Services: `mfemms`, `mfevtps`, `mfefire` |
| **Malwarebytes** | Endpoint Protection | Service/Process: `MBAMService` |
| **Bitdefender** | Endpoint Security | Service/Process: `bdservicehost` |
| **VMware** | Carbon Black Cloud | Install directory: `C:\Program Files\Confer` |

**Detection Method Priority**:
1. Windows Security Center (`AntivirusProduct` via WMI)
2. Microsoft Defender health check (`Get-MpComputerStatus`)
3. Running services and processes
4. Known installation directories

**Detection Script**: `threat model Windows/no EPP/implementation.ps`

---

## Password Managers

### macOS Password Managers

EDAMAME detects the following password managers on macOS through native applications and browser extensions:

#### Native Applications
| **Product** | **Detection Path** |
|-------------|-------------------|
| 1Password | `/Applications/1Password.app` |
| 1Password 7 (legacy) | `/Applications/1Password 7.app` or `/Applications/1Password7.app` |
| 1Password for Safari | `/Applications/1Password for Safari.app` |
| Bitwarden | `/Applications/Bitwarden.app` |
| LastPass | `/Applications/LastPass.app` or `/Applications/LastPass for Safari.app` |
| Dashlane | `/Applications/Dashlane.app` |
| Keeper | `/Applications/Keeper Password Manager.app` or `/Applications/Keeper for Safari.app` |
| Enpass | `/Applications/Enpass.app` |
| KeePassXC | `/Applications/KeePassXC.app` |
| NordPass | `/Applications/NordPass.app` |
| RoboForm | `/Applications/RoboForm.app` |
| Zoho Vault | `/Applications/Zoho Vault.app` |
| Proton Pass | `/Applications/Proton Pass.app` |
| Google Password Manager | `$HOME/Applications/Chrome Apps.localized/Google Password Manager.app` |

#### Browser Extensions
**Chromium-based browsers** (Chrome, Edge, Brave, Vivaldi):
- 1Password (stable & Beta)
- Bitwarden
- LastPass
- Dashlane
- Keeper
- Zoho Vault
- NordPass
- RoboForm
- KeePassXC-Browser
- Enpass
- Proton Pass

**Firefox**:
- Detected by scanning `extensions.json` in Firefox profiles for matching extension names

**Profile Locations**:
- Chrome: `$HOME/Library/Application Support/Google/Chrome`
- Edge: `$HOME/Library/Application Support/Microsoft Edge`
- Brave: `$HOME/Library/Application Support/BraveSoftware/Brave-Browser`
- Vivaldi: `$HOME/Library/Application Support/Vivaldi`
- Firefox: `$HOME/Library/Application Support/Firefox/Profiles`

**Detection Script**: `threat model macOS/no password manager/implementation.sh`

---

### Windows Password Managers

EDAMAME detects the following password managers on Windows through native installations and browser extensions:

#### Native Applications
Detected via Windows Registry uninstall entries and Microsoft Store:

- 1Password
- Bitwarden
- LastPass
- Dashlane
- Keeper
- Enpass
- KeePass / KeePassXC
- NordPass
- RoboForm
- Zoho Vault
- Proton Pass
- Sticky Password
- Kaspersky Password Manager

**Detection Method**:
1. Registry hives:
   - `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`
   - `HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*` (32-bit on 64-bit)
   - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`
2. Microsoft Store packages (`Get-AppxPackage -AllUsers`)

#### Browser Extensions
**Chromium-based browsers** (Chrome, Edge, Brave, Vivaldi, Opera):

**Chrome Web Store IDs**:
- 1Password: `aeblfdkhhhdcdjpifhhbdiojplfjncoa` (stable), `khgocmkkpikpnmmkgmdnfckapcdkgfaf` (Beta)
- Bitwarden: `nngceckbapebfimnlniiiahkandclblb`
- LastPass: `hdokiejnpimakedhajhdlcegeplioahd`
- Dashlane: `fdjamakpfbbddfjaooikfcpapjohcfmg`
- Keeper: `bfogiafebfohielmmehodmfbbebbbpei`
- Zoho Vault: `igkpcodhieompeloncfnbekccinhapdb`
- NordPass: `eiaeiblijfjekdanodkjadfinkhbfgcd`
- RoboForm: `pnlccmojcmeohlpggmfnbbiapkmbliob`
- KeePassXC-Browser: `oboonakemofpalcgghocfoadofidjkkk`
- Enpass: `kmcfomidfpdkfieipokbalgegidffkal`
- Proton Pass: `ghmbeldphafepmbegfdlkpapadhbakde`

**Microsoft Edge Add-ons IDs** (where they differ from Chrome):
- 1Password: `dppgmdbiimibapkepcbdbmkaabgiofem`
- Bitwarden: `jbkfoedolllekgbhcbcoahefnbanhhlh`
- KeePassXC-Browser: `pdffhmdngciaglkoonimfcmckehcpafo`

**Firefox**:
- Detected by scanning `extensions.json` for matching product names

**Profile Locations**:
- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data`
- Brave: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`
- Vivaldi: `%LOCALAPPDATA%\Vivaldi\User Data`
- Opera: `%APPDATA%\Opera Software\Opera Stable`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles`

**Detection Script**: `threat model Windows/no password manager/implementation.ps`

---

## Adding New Security Software

To extend detection for additional EPP or password manager products:

1. **Export the relevant threat model**:
   ```bash
   python3 src/cli/export.py threatmodel-macOS.json
   python3 src/cli/export.py threatmodel-Windows.json
   ```

2. **Edit the implementation script**:
   - For EPP: add detection logic to `threat model <Platform>/no EPP/implementation.{sh,ps}`
   - For Password Managers: add detection logic to `threat model <Platform>/no password manager/implementation.{sh,ps}`

3. **Re-import and test**:
   ```bash
   python3 src/cli/import.py threatmodel-<Platform>.json
   ./tests/run-tests.sh
   ```

4. **Update signatures**:
   ```bash
   python3 src/publish/update-models.py threatmodel-macOS.json threatmodel-Windows.json
   ```

5. **Update this documentation** with the newly supported products.

---

## Notes

- **EPP Detection Philosophy**: The scripts prioritize accuracy over completeness. Detection methods verify that security software is not only installed but also actively running and protecting the system.

- **Password Manager Detection**: Both native applications and browser extensions are checked. The detection covers the most popular password managers used in enterprise and personal environments.

- **Privacy**: All detection is performed locally. No data about installed software is transmitted without explicit user consent.

- **False Negatives**: Some enterprise deployments may use custom installation paths or service names. If a legitimate security product is not detected, please open an issue with details about the product and detection method.

