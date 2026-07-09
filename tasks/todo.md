# Forensic Imager Refactor — Task List

Status legend: [x] done  [ ] pending

- [x] **T1** Scaffold package: `constants.py`, `__init__.py`, `__main__.py`; move `main()`
      verbatim into `cli.py`; `forensic_imager.py` becomes a thin launcher. (Checkpoint A)
- [x] **T2** Extract `hashing.py` (`HashResult` + `calculate_file_hashes`); wire `--verify-only`.
- [x] **T3** Extract `devices.py` (`get_device_ro_status`, `get_device_size`,
      `get_available_space`); wire CLI.
- [x] **T4** Extract `acquisition.py` core loop + `BadSector`/`AcquisitionResult`;
      byte-identical full acquire. (Checkpoint B)
- [x] **T5** Resume logic (`plan_resume`/inline pre-hash validation) inside `run_acquisition`.
- [x] **T6** Extract `reporting.py` (`write_acquisition_report`, verbatim format).
- [x] **T7** Extract `custody.py` (`write_audit_and_custody_log`, byte-identical).
- [x] **T8** Final assembly: confirm `cli.py` only orchestrates; write `tasks/plan.md` +
      `tasks/todo.md`; full parity verification. (Checkpoint C)

## Verification result

Engine parity harness: ALL PASS (hashing, device size, custody, byte-identical copy,
SHA-512 match, resume parity). Package compiles; both entry points reach the root gate.
