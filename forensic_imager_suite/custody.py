"""Chain of custody logging.

Appends a human-readable forensic transfer record to the custody log. The header is
written only once (on first creation); every subsequent call appends a new record.
"""
import os


def write_audit_and_custody_log(log_path, metadata):
    """سجل تدقيق وسلسلة حيازة (Chain of Custody) متكامل الأركان القانونية والنقل الجنائي"""
    try:
        file_exists = os.path.exists(log_path)
        with open(log_path, "a") as f:
            if not file_exists:
                f.write("="*80 + "\n")
                f.write("                       OFFICIAL FORENSIC CHAIN OF CUSTODY LOG\n")
                f.write("="*80 + "\n")
            f.write(f"TIMESTAMP:           {metadata['timestamp']}\n")
            f.write(f"Action/Operation:    {metadata['action']}\n")
            f.write(f"Case Number ID:      {metadata['case_number']}\n")
            f.write(f"Evidence ID Tag:     {metadata['evidence_id']}\n")
            f.write(f"Released By (From):  {metadata['released_by']}\n")
            f.write(f"Received By (To):    {metadata['examiner']}\n")
            f.write(f"Purpose of Transfer: {metadata['purpose']}\n")
            f.write(f"Target Image File:   {metadata['destination']}\n")
            f.write(f"Verification HASH:   {metadata['sha512']}\n")
            f.write("-" * 80 + "\n")
    except Exception as e:
        print(f"[!] Warning: Unable to write chain of custody log: {e}")
