# EDAMAME Endpoint Threat Models

## Table of Contents
- [Overview](#overview)
- [Threat Dimensions](#threat-dimensions)
- [Naming Conventions](#naming-conventions)
- [Model Structure](#model-structure)
  - [JSON Format](#json-format)
  - [Key Fields](#key-fields)
- [Implementation Types](#implementation-types)
  - [System Checks](#system-checks)
  - [Command Line Checks](#command-line-checks)
  - [Business Rules](#business-rules)
- [Platform Coverage](#platform-coverage)
- [Security Assessment](#security-assessment)
  - [Severity Classification](#severity-classification)
  - [Compliance Frameworks](#compliance-frameworks)
- [Privacy Protection](#privacy-protection)
- [Additional Features](#additional-features)
  - [Internationalization](#internationalization)
  - [Implementation Details](#implementation-details)
  - [Remediation Guidance](#remediation-guidance)
- [Contact and Resources](#contact-and-resources)

## Overview

This repository contains the threat models used by the EDAMAME Security application to compute its Security Score. These models are based on industry-standard benchmarks including NIST and CIS, as well as other authoritative sources.

The EDAMAME Security platform leverages these models to provide comprehensive security posture assessment while ensuring user privacy and preventing administrative overreach.

## Threat Dimensions

Security threats are categorized along 5 key dimensions:

| Dimension | Description |
|-----------|-------------|
| **Applications** | Application authorizations, code signing, EPP/antivirus, etc. |
| **Network** | Network configuration, exposed services, unsafe connections |
| **Credentials** | Password policies, biometrics, 2FA, exposed credentials |
| **System Integrity** | MDM profiles, jailbreaking, 3rd party administrative access |
| **System Services** | System configuration, service vulnerabilities |

## Naming Conventions

Threat names follow these conventions:
- Describe the threat directly (not its remediation)
- No hyphens (`-`)
- Spaces are preferred over underscores (`_`)
- No special characters
- Lowercase except for acronyms and commercial names
- Example: `Chrome not uptodate`

## Model Structure

Each threat model is structured as a JSON file that defines:
1. **Threat metadata**: Information about the threat, including its name, description, severity, and impact
2. **Detection logic**: The checks and conditions used to detect the presence of the threat
3. **Remediation guidance**: Recommended actions to mitigate the threat
4. **References**: Links to standards, benchmarks, and other sources of information

### JSON Format

Each threat model file follows a standardized format:

```json
{
  "name": "threat model [Platform]",
  "extends": "none",
  "date": "Last update date",
  "signature": "Cryptographic signature of the model",
  "metrics": [
    {
      "name": "Threat name",
      "metrictype": "bool",
      "dimension": "One of the 5 dimensions",
      "severity": 1-5,
      "scope": "Platform-specific or generic",
      "tags": ["Compliance standards", "Benchmarks"],
      "description": [
        { "locale": "EN", "title": "Title", "summary": "Description" },
        { "locale": "FR", "title": "Titre", "summary": "Description" }
      ],
      "implementation": { ... },
      "remediation": { ... },
      "rollback": { ... }
    }
  ]
}
```

### Key Fields

**Top Level Properties:**
- **name**: The unique identifier of the threat model
- **extends**: Inheritance model, if applicable 
- **date**: Last update timestamp
- **signature**: Cryptographic signature for integrity verification
- **metrics**: Array of threat definitions

**Metric Properties:**
- **name**: The threat identifier
- **metrictype**: Type of measurement (typically boolean)
- **dimension**: The security dimension the threat belongs to
- **severity**: Impact rating from 1 (low) to 5 (critical)
- **scope**: Whether the threat is platform-specific or generic
- **tags**: Compliance references (e.g., CIS Benchmark, ISO 27001, SOC 2)
- **description**: Localized explanations of the threat
- **implementation**: Detection logic
- **remediation**: Steps to resolve the threat
- **rollback**: Steps to revert remediation if needed

## Implementation Types

Threat models employ different detection methods depending on the nature of the security check:

### System Checks
Direct checks of system configuration, file presence, or settings that can be evaluated through standard APIs.

### Command Line Checks
Safe, predefined commands that gather information about the system state. These commands are carefully vetted to ensure they cannot cause harm to the system.

### Business Rules
Specialized checks that execute local scripts in userspace, leveraging the `EDAMAME_BUSINESS_RULES_CMD` environment variable. These scripts operate entirely on the user's device and implement organization-specific security policies without compromising user privacy.

The business rules framework allows organizations to define custom security checks while ensuring that:
- Scripts run locally in userspace only
- Only the final check result (pass/fail) is transmitted when reporting the security score
- The detailed output of the script remains available only on the local device
- No sensitive user data is sent to remote servers

This approach prevents potential abuse by administrators while maintaining the privacy and security of end users. Business rules can only access information that a normal user process could access, providing an additional layer of protection against privacy violations.

## Platform Coverage

EDAMAME provides threat models for multiple platforms:

| Platform | Coverage |
|----------|----------|
| **Android** | Android 11+ |
| **iOS** | iOS 15+ |
| **Linux** | Various distributions |
| **macOS** | macOS-specific threats |
| **Windows** | Windows-specific threats |

Each platform model contains:
1. **Platform-specific threats**: Threats unique to the platform's architecture
2. **Generic threats**: Common threats applicable across multiple platforms
3. **Implementation differences**: Platform-appropriate detection methods for similar threats

## Security Assessment

### Severity Classification

Threats are classified on a scale from 1 to 5:

| Level | Severity | Description |
|-------|----------|-------------|
| 1 | **Low** | Represents good security practice but minimal immediate risk |
| 2 | **Medium-Low** | May represent a security weakness |
| 3 | **Medium** | Significant security risk in specific circumstances |
| 4 | **High** | Serious security risk for most users |
| 5 | **Critical** | Severe security risk requiring immediate remediation |

### Compliance Frameworks

Threat models leverage industry standards and compliance frameworks:

| Framework | Description |
|-----------|-------------|
| **CIS Benchmarks** | Center for Internet Security standardized configurations |
| **ISO 27001/2** | International security management standards |
| **SOC 2** | Service Organization Control framework |
| **Personal Posture** | EDAMAME-specific recommendations for personal device security |

## Privacy Protection

EDAMAME's threat model implementation follows a privacy-by-design approach. The security assessment framework ensures that:

1. Only the result of a check (pass/fail/not applicable) is transmitted when reporting the security score
2. Raw data and detailed script outputs remain on the local device
3. Checks cannot access privileged information beyond what's available to the user
4. No personally identifiable information is collected or transmitted without explicit consent

This architecture intentionally prevents administrative abuse of security checks and guarantees user privacy, in line with EDAMAME Technologies' commitment to building security tools that respect user autonomy and privacy.

## Additional Features

### Internationalization

Threat descriptions support multiple languages, currently:
- English (EN)
- French (FR)

Each threat description, remediation step, and user-facing element is internationalized to provide native language support.

### Implementation Details

Each threat implementation contains:
- **system**: Target operating system
- **minversion/maxversion**: Version compatibility range
- **class**: Implementation method (internal, command, business_rules)
- **elevation**: Required permission level (user, admin)
- **target**: Specific check to perform
- **education**: Optional educational materials

### Remediation Guidance

Remediation paths include:
- **Direct links**: To official documentation for standard remediation
- **HTML content**: Rich formatted guidance for complex issues
- **Internal tools**: For threats that can be addressed through EDAMAME tooling