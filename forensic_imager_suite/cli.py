"""Command-line interface and orchestration for the Forensic Imager Suite.

Parses arguments, performs pre-flight validation, and coordinates the hashing,
device, acquisition, reporting, and custody modules. No imaging logic lives here —
this module only wires the engine together.
"""
import os
import sys
import argparse
import time

from . import devices
from . import hashing
from . import acquisition
from . import reporting
from . import custody
from .constants import DEFAULT_BLOCK_SIZE, MIN_BLOCK_SIZE, MAX_BLOCK_SIZE, SECTOR_SIZE


def main():
    if os.geteuid() != 0:
        print("[!] Critical Error: Root privileges required. Run with 'sudo'.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Professional Forensic Image Acquisition & Verification Suite")
    parser.add_argument("-s", "--source", required=True, help="Path to source device/file")
    parser.add_argument("-d", "--destination", required=True, help="Path to destination image file")
    parser.add_argument("-b", "--block-size", type=int, default=DEFAULT_BLOCK_SIZE, help="Block size (Must be aligned to 512-byte sectors)")
    parser.add_argument("-r", "--resume", action="store_true", help="Resume an interrupted imaging process safely")
    parser.add_argument("--legacy-md5", action="store_true", help="Enable MD5 hashing algorithm context")
    parser.add_argument("--verify-only", action="store_true", help="Perform real cryptographic verification against expected hashes")
    # مدخلات التحقق الحقيقي من الهاشات المتوقعة
    parser.add_argument("--expected-sha512", default=None, help="Expected SHA-512 hash string for verification verification")
    parser.add_argument("--expected-sha256", default=None, help="Expected SHA-256 hash string for verification verification")
    # الميتاداتا القانونية لسلسلة الحيازة الحقيقية (Chain of Custody Metadata)
    parser.add_argument("--case-number", default="CASE-N/A", help="Forensic Case Identifier")
    parser.add_argument("--evidence-id", default="EVID-N/A", help="Evidence Unit Tag")
    parser.add_argument("--examiner", default="EXAM-N/A", help="Current Forensic Examiner (Receiver)")
    parser.add_argument("--released-by", default="N/A", help="Previous Custodian / Person who released the evidence")
    parser.add_argument("--purpose", default="Forensic Image Acquisition & Preservation", help="Reason for evidence transfer or action")
    args = parser.parse_args()

    start_time = time.time()
    log_file_path = f"{args.destination}.custody.log"

    print("\n" + "="*65)
    print("      PROFESSIONAL FORENSIC IMAGER & CHAIN OF CUSTODY ENGINE")
    print("="*65)

    # 1. القيد الصارم لمحاذاة حجم البلوك (Sector Alignment Boundary Check)
    if args.block_size <= MIN_BLOCK_SIZE - 1 or args.block_size > MAX_BLOCK_SIZE:
        print("[!] Critical Error: Block size must be between 1B and 16MB.")
        sys.exit(1)
    if args.block_size % SECTOR_SIZE != 0:
        print(f"[!] Critical Error: Block size ({args.block_size}) is not aligned to 512-byte sectors (Physical Geometry Requirement).")
        sys.exit(1)

    # 2. إصلاح نمط التحقق الصافي وحقن منطق المطابقة الحقيقي (--verify-only)
    if args.verify_only:
        print(f"[*] Mode: CRITICAL INTEGRITY VERIFICATION")
        print(f"[*] Target Image File: {args.destination}")
        if not os.path.exists(args.destination):
            print(f"[!] Verification Error: Image file '{args.destination}' not found.")
            sys.exit(1)

        print("[*] Computing cryptographic signatures. Please wait...")
        v = hashing.calculate_file_hashes(args.destination, args.block_size, compute_md5=args.legacy_md5)
        v_512, v_256, v_md5 = v.sha512, v.sha256, v.md5
        print(f"[+] Calculated SHA-512: {v_512}")
        print(f"[+] Calculated SHA-256: {v_256}")

        # إجراء عملية المقارنة الجنائية الحقيقية (Real Verification Validation)
        passed = True
        if args.expected_sha512:
            if v_512.lower() == args.expected_sha512.lower():
                print("[+] SHA-512 VERIFICATION: MATCH / PASS")
            else:
                print("[!] SHA-512 VERIFICATION: MISMATCH / FAIL")
                passed = False
        if args.expected_sha256:
            if v_256.lower() == args.expected_sha256.lower():
                print("[+] SHA-256 VERIFICATION: MATCH / PASS")
            else:
                print("[!] SHA-256 VERIFICATION: MISMATCH / FAIL")
                passed = False

        status_txt = "VERIFICATION PASS" if passed else "VERIFICATION FAIL"
        if not args.expected_sha512 and not args.expected_sha256:
            status_txt = "HASH GENERATED (No expected hash supplied for validation)"
            print("[*] Note: No expected hashes provided via CLI. Standing as static signature generation.")

        # تسجيل المعاملة في سلسلة الحيازة الرسمية
        custody.write_audit_and_custody_log(log_file_path, {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            "action": f"Cryptographic Verification Only ({status_txt})",
            "case_number": args.case_number, "evidence_id": args.evidence_id,
            "released_by": args.released_by, "examiner": args.examiner, "purpose": args.purpose,
            "destination": args.destination, "sha512": v_512
        })
        sys.exit(0 if passed else 1)

    # 3. الفحوصات الاستقصائية التقليدية للملفات والمنافذ
    if not os.path.exists(args.source):
        print(f"[!] Critical Error: Source path '{args.source}' not found.")
        sys.exit(1)

    if os.path.abspath(args.source) == os.path.abspath(args.destination):
        print("[!] Critical Error: Structural loop risk! Source and destination paths are textually identical.")
        sys.exit(1)

    source_size = devices.get_device_size(args.source)
    dest_dir = os.path.dirname(os.path.abspath(args.destination)) or "."
    try:
        free_space = devices.get_available_space(dest_dir)
        available_bytes = free_space
        if source_size > 0 and available_bytes < source_size:
            print(f"[!] Critical Error: Insufficient space. Required: {source_size} B, Available: {available_bytes} B.")
            sys.exit(1)
    except Exception as e:
        print(f"[*] Warning: Direct storage allocation checks bypassed: {e}")

    # إصلاح التوصيف الجنائي لـ blockdev: هي مؤشر استشاري فقط (Advisory Only)
    is_write_blocked = devices.get_device_ro_status(args.source)
    if not is_write_blocked:
        print(f"[!] Warning: Source write-block status: Advisory only. Kernel lock not detected!")
    else:
        print(f"[+] Source write-block status: Advisory locked via kernel flag.")

    # 4. تشغيل المحرك
    result = acquisition.run_acquisition(
        source=args.source,
        destination=args.destination,
        block_size=args.block_size,
        resume=args.resume,
        compute_md5=args.legacy_md5,
        start_time=start_time,
        source_size=source_size,
        is_write_blocked=is_write_blocked,
    )

    # إنشاء التقرير الاستقصائي الفني الشامل للمحاكم والجهات الفنية العليا
    reporting.write_acquisition_report(args.destination + ".report", {
        "case_number": args.case_number,
        "evidence_id": args.evidence_id,
        "examiner": args.examiner,
        "start_time": start_time,
        "duration": result.duration,
        "acquisition_speed": result.acquisition_speed,
        "block_size": args.block_size,
        "resume": args.resume,
        "is_write_blocked": is_write_blocked,
        "destination": args.destination,
        "copied_bytes": result.copied_bytes,
        "status_str": result.status_str,
        "read_errors_detected": result.read_errors_detected,
        "bad_sectors_map": result.bad_sectors_map,
        "dest_sha512": result.dest_sha512,
        "dest_sha256": result.dest_sha256,
        "src_sha512": result.src_sha512,
        "src_sha256": result.src_sha256,
        "dest_md5": result.dest_md5,
        "src_md5": result.src_md5,
    })

    # 6. حقن وتحديث السجل الرسمي لسلسلة الحيازة لتوثيق نقل العهدة والموثوقية القانونية بالكامل
    custody.write_audit_and_custody_log(log_file_path, {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        "action": f"Physical Acquisition Session (Resume Mode: {args.resume}, Status: {result.status_str})",
        "case_number": args.case_number, "evidence_id": args.evidence_id,
        "released_by": args.released_by, "examiner": args.examiner, "purpose": args.purpose,
        "destination": args.destination, "sha512": result.dest_sha512
    })


if __name__ == "__main__":
    main()
