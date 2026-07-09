#!/usr/bin/env python3
"""Thin launcher for the Forensic Imager Suite package.

Preserves the `sudo ./forensic_imager.py ...` invocation documented in the README
while the real implementation lives in the `forensic_imager_suite` package.
"""
from forensic_imager_suite.cli import main

if __name__ == "__main__":
    main()
