# Forensic Imager & Chain of Custody Engine

A professional, lightweight Python 3 forensic imaging suite designed for bit-stream acquisition and preservation of digital evidence. The tool strictly adheres to forensic standards, implementing logical integrity validation, historical session resume logic, physical dynamic zero-padding for defective hardware sectors, and comprehensive Chain of Custody logging.

## Key Features

* **Bit-Stream Copying & Verification:** Computes cryptographic signatures concurrently using **SHA-512** and **SHA-256** (with legacy **MD5** context support).
* **Physical Sector Degradation Handling:** Employs precise `errno.EIO` filtering. If a bad sector is encountered, it applies mathematical zero-padding to sustain alignment while mapping out bad blocks in an independent CSV layout.
* **Intelligent Session Resume:** Validates historical target segments via a robust pre-hashing pipeline before safely resuming interrupted imaging operations.
* **Legal Compliance Auditing:** Generates standard courtroom-ready Forensic Acquisition Reports and continuous Chain of Custody transaction logs.

## Setup & Installation

Ensure you are running on a Linux distribution (e.g., **Kali Linux**) with root privileges:

```bash
git clone [https://github.com/yosrialqaddasi00-tech/Forensic-Imager-Suite.git](https://github.com/yosrialqaddasi00-tech/Forensic-Imager-Suite.git)
cd Forensic-Imager-Suite
chmod +x forensic_imager.py

sudo ./forensic_imager.py -s /dev/sdb -d /case_data/evidence_disk.dd --case-number "CASE-2026-001" --evidence-id "EVID-01" --examiner "yosrialqaddasi00-tech"


