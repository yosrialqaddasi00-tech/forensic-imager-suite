# Plan: Refactor Forensic Imager into a Modular Package

> Canonical copy of the approved plan (also at the plan-mode plan file). Status: **implemented & verified**.

## Context

`forensic_imager.py` was a ~446-line single-file forensic imaging tool (bit-stream
acquisition, SHA-512/256/+MD5, EIO bad-sector zero-padding, session resume, CSV
bad-sector map, acquisition report, chain-of-custody logging). Goal: split it into a
clean `forensic_imager_suite/` package with **zero behavior change**. Automated tests
were explicitly deferred by the user — verification is manual/engine-parity.

## Target Layout

```
forensic_imager_suite/
  __init__.py      version
  __main__.py      `python -m forensic_imager_suite` entry
  constants.py     SECTOR_SIZE, DEFAULT/MIN/MAX_BLOCK_SIZE
  hashing.py       HashResult + calculate_file_hashes
  devices.py       get_device_ro_status, get_device_size, get_available_space
  acquisition.py   BadSector, AcquisitionResult, run_acquisition (copy loop + resume)
  reporting.py     write_acquisition_report
  custody.py       write_audit_and_custody_log
  cli.py           argparse + orchestration (was main())
forensic_imager.py  thin launcher (preserves `sudo ./forensic_imager.py`)
```

## Dependency Graph

`constants` (leaf) → `hashing`, `devices`, `custody`, `reporting` → `acquisition` → `cli` → `__main__`.

## Verification (what was run)

Engine parity harness (no root needed — engine functions don't gate on `geteuid`):
- `calculate_file_hashes` vs original: identical (md5 + `limit_size` pre-hash) ✅
- `get_device_size` on a file: identical ✅
- `write_audit_and_custody_log` (header + append): byte-identical ✅
- `run_acquisition` full copy: byte-identical to source; dest SHA-512 == `sha512sum` ✅
- `run_acquisition` resume: resumed image == full reference image ✅
- `py_compile` all modules OK; `python -m forensic_imager_suite` and `./forensic_imager.py`
  both reach the root-privilege gate identically ✅

The acquisition **report** text was copied verbatim from the original inline block
(variable names swapped for a `ctx` dict); the custody log was verified byte-identical.
The EIO bad-sector path cannot be triggered on a healthy file — verified by code review
of the zero-padding branch.

## Follow-up (out of scope, per user)

A `pytest` suite (unit + fake-device integration) is recommended next.
