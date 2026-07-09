# Forensic Imager & Chain of Custody Engine

A professional, lightweight Python 3 forensic imaging suite for **bit-stream acquisition
and preservation of digital evidence**. The tool strictly adheres to forensic standards:
it performs logical integrity validation, safely resumes interrupted sessions, applies
physical zero-padding for defective hardware sectors, and produces courtroom-ready
acquisition reports plus a continuous Chain of Custody log.

The suite is implemented as a small, dependency-free Python package
(`forensic_imager_suite/`) launched by a thin `forensic_imager.py` wrapper.

---

## Key Features

* **Bit-Stream Copying & Verification** — Copies a device or file byte-for-byte while
  computing cryptographic signatures concurrently using **SHA-512** and **SHA-256**
  (legacy **MD5** context support is available via `--legacy-md5`).
* **Physical Sector Degradation Handling** — Employs precise `errno.EIO` filtering. When
  a bad sector is hit, the tool substitutes zero bytes to preserve storage alignment and
  records the defective block in an independent CSV map.
* **Intelligent Session Resume** — Before resuming an interrupted image, it validates the
  already-written portion against the source via a pre-hashing pipeline, then continues
  seamlessly from the last verified offset.
* **Legal Compliance Auditing** — Generates standard courtroom-ready Forensic Acquisition
  Reports and appends a continuous Chain of Custody transaction log for every action.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| **Python**  | 3.7 or newer (uses f-strings and the `dataclasses` module) |
| **OS**      | Linux (developed and tested on Kali / Debian-based distributions) |
| **Root**    | Required — the tool refuses to run otherwise (`geteuid() != 0`) |
| **`blockdev`** | Provided by `util-linux`; used for device size and write-block probes. On a regular file these probes fall back gracefully, so files can be imaged without `blockdev`. |

**No third-party Python packages are required** — the suite is built entirely on the
Python standard library. See [`requirements.txt`](requirements.txt).

---

## Installation

```bash
git clone https://github.com/yosrialqaddasi00-tech/Forensic-Imager-Suite.git
cd Forensic-Imager-Suite
chmod +x forensic_imager.py
```

No `pip install` step is necessary.

---

## Usage

The tool can be launched either through the wrapper script or as a module:

```bash
sudo ./forensic_imager.py -s /dev/sdb -d /case_data/evidence_disk.dd \
    --case-number "CASE-2026-001" --evidence-id "EVID-01" --examiner "yosrialqaddasi00-tech"

# equivalent:
sudo python3 -m forensic_imager_suite -s /dev/sdb -d /case_data/evidence_disk.dd ...
```

### Common scenarios

**1. Basic acquisition**

```bash
sudo ./forensic_imager.py -s /dev/sdb -d /case_data/evidence_disk.dd \
    --case-number "CASE-2026-001" --evidence-id "EVID-01" --examiner "Jane Doe"
```

**2. Verify an existing image against expected hashes**

```bash
sudo ./forensic_imager.py -s /dev/sdb -d /case_data/evidence_disk.dd --verify-only \
    --expected-sha512 "<known SHA-512>" --expected-sha256 "<known SHA-256>"
```

If no expected hash is supplied, the tool prints the computed signatures without judging
pass/fail. Exit code is `0` on a match and `1` on a mismatch (or when the image is missing).

**3. Resume an interrupted acquisition**

```bash
sudo ./forensic_imager.py -s /dev/sdb -d /case_data/evidence_disk.dd -r \
    --case-number "CASE-2026-001"
```

The tool derives the resume offset from the existing destination size, pre-hashes that
portion against the source, and aborts if the historical segments do not align.

**4. Include a legacy MD5 footprint**

```bash
sudo ./forensic_imager.py -s /dev/sdb -d /case_data/evidence_disk.dd --legacy-md5
```

**5. Full Chain of Custody metadata**

```bash
sudo ./forensic_imager.py -s /dev/sdb -d /case_data/evidence_disk.dd \
    --case-number "CASE-2026-001" --evidence-id "EVID-01" \
    --examiner "Jane Doe" --released-by "Evidence Custodian" \
    --purpose "Routine forensic acquisition"
```

---

## Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `-s`, `--source` | *(required)* | Path to the source device or file. |
| `-d`, `--destination` | *(required)* | Path to the destination image file. |
| `-b`, `--block-size` | `4096` | Read/write block size. Must be aligned to **512-byte sectors** and between **1 B and 16 MB**. |
| `-r`, `--resume` | off | Safely resume an interrupted imaging session. |
| `--legacy-md5` | off | Enable the legacy **MD5** hashing context. |
| `--verify-only` | off | Verify an existing image against expected hashes instead of imaging. |
| `--expected-sha512` | none | Expected SHA-512 hash for verification. |
| `--expected-sha256` | none | Expected SHA-256 hash for verification. |
| `--case-number` | `CASE-N/A` | Forensic case identifier (Chain of Custody). |
| `--evidence-id` | `EVID-N/A` | Evidence unit tag (Chain of Custody). |
| `--examiner` | `EXAM-N/A` | Current forensic examiner / receiver. |
| `--released-by` | `N/A` | Previous custodian who released the evidence. |
| `--purpose` | `Forensic Image Acquisition & Preservation` | Reason for the transfer / action. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (or verification **pass**). |
| `1` | Root privileges missing, invalid arguments, source/destination problem, insufficient space, critical I/O abort, integrity/resume failure, or verification **fail**. |

---

## Output Artifacts

For a destination `<image>.dd` the tool produces:

| File | Description |
|------|-------------|
| `<image>.dd` | The bit-stream image (zero-padded where bad sectors were encountered). |
| `<image>.dd.report` | Courtroom-ready acquisition report: environment, timing, speeds, status, bad-sector index, and the full cryptographic footprint. |
| `<image>.dd.custody.log` | Append-only Chain of Custody log; the header is written once, then each action appends a record. |
| `<image>.dd.bad_sectors.csv` | *(only if defects were found)* A CSV map of defective sector offsets, sizes, and error types. |

---

## How It Works (Architecture)

The suite is organized as a package so each concern lives in its own module:

```
forensic_imager_suite/
├── __main__.py     # `python -m forensic_imager_suite` entry point
├── cli.py          # Argument parsing + orchestration (was main())
├── constants.py    # Sector/block-size limits and shared constants
├── hashing.py      # calculate_file_hashes() + HashResult
├── devices.py      # Device probes: get_device_ro_status / get_device_size / get_available_space
├── acquisition.py  # Core copy loop, bad-sector handling, resume: run_acquisition()
├── reporting.py    # write_acquisition_report()
└── custody.py      # write_audit_and_custody_log()
```

`cli.py` wires the engine together: it validates arguments, probes the device, calls
`acquisition.run_acquisition(...)`, then emits the report and custody record. All imaging
and hashing logic lives in the engine modules, keeping `cli.py` free of low-level details.

### Chain of Custody

Every acquisition and every `--verify-only` run appends a structured record to
`<image>.dd.custody.log` capturing the timestamp, action, case/evidence identifiers,
releasing and receiving parties, purpose, target file, and the governing SHA-512 hash.

### Bad-Sector Handling

During acquisition, a read error with `errno == EIO` is treated as a physically defective
sector. The tool pads the destination with an equivalent run of zero bytes (preserving
alignment), logs the offset, and — when any degradation occurs — marks the source hash as
`INTEGRITY UNVERIFIABLE` while still recording the destination's mathematical baseline.

### Integrity & Resume

On resume (`-r`), the offset is taken from the existing destination size. The tool
pre-hashes that many bytes of both the destination and the source; if they do not match
(or either is unreadable), the resume is aborted to prevent producing misleading evidence.
Otherwise acquisition continues from the verified offset with the hash state carried over.

---

## Notes & Caveats

* The kernel **write-block** probe is **advisory only** — it reports the `blockdev`
  read-only flag but does not itself enforce a hardware write block. Always use a
  verified write-blocker for real evidence handling.
* Block size must be a multiple of 512 bytes (the physical sector boundary).
* Bad-sector simulation cannot be exercised on a healthy file; verify behavior on faulty
  media or a purpose-built faulty device before relying on it operationally.
