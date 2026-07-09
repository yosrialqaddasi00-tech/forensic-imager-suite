"""Forensic acquisition report generation.

Produces the courtroom-ready text report. Output formatting is preserved exactly
from the original engine so historical reports remain byte-comparable.
"""
import os
import time


def write_acquisition_report(report_path, ctx):
    """Generate the investigative acquisition baseline report from a context dict."""
    try:
        with open(report_path, "w") as rep:
            rep.write("="*75 + "\n")
            rep.write("                         FORENSIC ACQUISITION REPORT\n")
            rep.write("="*75 + "\n")
            rep.write(f"Case Identifier String:   {ctx['case_number']}\n")
            rep.write(f"Evidence Unit Identifier: {ctx['evidence_id']}\n")
            rep.write(f"Active Forensic Examiner: {ctx['examiner']}\n")
            rep.write("-" * 75 + "\n")
            rep.write(f"Platform Hostname Node:   {os.uname()[1]}\n")
            rep.write(f"Operating System Kernel:  {os.uname().sysname} {os.uname().release}\n")
            rep.write(f"Execution Start Window:   {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ctx['start_time']))}\n")
            rep.write(f"Execution End Window:     {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
            rep.write(f"Total Processing Time:    {ctx['duration']} seconds\n")
            rep.write(f"Pipeline Running Velocity:{ctx['acquisition_speed']} MB/s\n")
            rep.write(f"Sector Alignment Boundary:{ctx['block_size']} Bytes\n")
            rep.write(f"Session Resume Flags:     {ctx['resume']}\n")
            rep.write(f"Kernel Write-Block Status:{'Advisory Locked' if ctx['is_write_blocked'] else 'Advisory Unlocked / Warning'}\n")
            rep.write(f"Target Destination Image: {ctx['destination']}\n")
            rep.write(f"Physical Acquired Bytes:  {ctx['copied_bytes']} Bytes\n")
            rep.write(f"Pipeline Resolution State:{ctx['status_str']}\n")
            rep.write(f"Defective Block Clusters: {len(ctx['bad_sectors_map'])}\n")

            if ctx['read_errors_detected']:
                rep.write("\nOFFICIAL FORENSIC DISCLOSURE AND MANDATE:\n")
                rep.write("  Physical input read degradation occurred during the acquisition phase. The destination\n")
                rep.write("  image file geometry was padded with zero-byte structures to enforce matching storage\n")
                rep.write("  alignment. The destination hashes provided below establish the unique mathematical\n")
                rep.write("  baseline for all derivative discovery and verification steps.\n")

            if ctx['bad_sectors_map']:
                rep.write("-" * 75 + "\n")
                rep.write("                     DEFECTIVE HARDWARE SECTOR CLUSTER INDEX\n")
                for item in ctx['bad_sectors_map']:
                    rep.write(f"Sector Bad Offset Location: {item['offset']} (Sector Block Size: {item['size']})\n")

            rep.write("-"*75 + "\n")
            rep.write("                         CRYPTOGRAPHIC FOOTPRINT INDEX\n")
            rep.write(f"SHA-512 Destination Baseline: {ctx['dest_sha512']}\n")
            rep.write(f"SHA-512 Source Reference:     {ctx['src_sha512']}\n\n")
            rep.write(f"SHA-256 Destination Baseline: {ctx['dest_sha256']}\n")
            rep.write(f"SHA-256 Source Reference:     {ctx['src_sha256']}\n\n")
            rep.write(f"MD5 Destination (Legacy Mode):{ctx['dest_md5']}\n")
            rep.write(f"MD5 Source Reference (Legacy):{ctx['src_md5']}\n")
            rep.write("="*75 + "\n")

        print(f"[*] Investigative acquisition baseline report saved at: {report_path}")
    except Exception as e:
        print(f"[!] Failed to output final report file layout: {e}")
