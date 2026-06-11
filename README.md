# DecodeLabs Task 5 - File Integrity and Malware Indicator Scanner

## Overview
The File Integrity and Malware Indicator Scanner is a Python-based cybersecurity tool that analyzes files for integrity and potential security risks.

The scanner generates multiple cryptographic hashes and identifies suspicious indicators that may suggest malicious activity.

## Features
- MD5 hash generation
- SHA-1 hash generation
- SHA-256 hash generation
- File integrity verification
- Suspicious extension detection
- Malware indicator scanning
- Risk score calculation
- Security classification
- Recommended security actions

## Technologies Used
- Python 3
- hashlib
- os

## Project File

```text
file_integrity_scanner.py
```

## How to Run

```bash
python file_integrity_scanner.py
```

or

```bash
py file_integrity_scanner.py
```

## Example

Input:

```text
sample.exe
```

Output:

```text
Risk Score: 8
Status: High Risk
Recommended Action: Do not execute. Escalate for malware analysis.
```

## Risk Levels

- Low Risk
- Suspicious
- High Risk

## Author

Muhammad Abubakar Farooq

## Internship

DecodeLabs Cyber Security Internship 2026
