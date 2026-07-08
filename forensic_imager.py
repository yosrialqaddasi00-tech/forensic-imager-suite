#!/usr/bin/env python3
import os
import sys
import argparse
import hashlib
import time
import subprocess
import errno
import csv

def get_device_ro_status(device):
    try:
        result = subprocess.run(["blockdev", "--getro", device], capture_output=True, text=True)
        return result.stdout.strip() == "1"
    except Exception:
        return False

def get_device_size(device_path):
    try:
        result = subprocess.run(["blockdev", "--getsize64", device_path], capture_output=True, text=True)
        return int(result.stdout.strip())
    except Exception:
        try:
            return os.path.getsize(device_path)
        except Exception:
            return 0

def calculate_file_hashes(file_path, block_size, compute_md5=False, limit_size=None):
    """حساب الهاشات بنطاق محدد، مع تخطي أخطاء القراءة الفيزيائية لغرض مقارنة الاستكمال السليم"""
    h_sha512 = hashlib.sha512()
    h_sha256 = hashlib.sha256()
    h_md5 = hashlib.md5() if compute_md5 else None
    bytes_read = 0
    zero_chunk = b'\x00' * block_size
    
    try:
        fd = os.open(file_path, os.O_RDONLY)
        try:
            while True:
                to_read = block_size
                if limit_size is not None:
                    if bytes_read >= limit_size:
                        break
                    to_read = min(block_size, limit_size - bytes_read)
                
                try:
                    chunk = os.read(fd, to_read)
                    if not chunk:
                        break
                except OSError as err:
                    # حل مشكلة الجنايات في الـ Resume: إذا واجهنا قطاعاً تالفاً أثناء قراءة المصدر للتحقق،
                    # نقوم بمحاكاة الأصفار (Zero-Padding) تماماً كما فعلت الأداة في الجلسة السابقة
                    if err.errno == errno.EIO:
                        chunk = zero_chunk[:to_read]
                        os.lseek(fd, bytes_read + len(chunk), os.SEEK_SET)
                    else:
                        raise
                
                h_sha512.update(chunk)
                h_sha256.update(chunk)
                if compute_md5:
                    h_md5.update(chunk)
                bytes_read += len(chunk)
                
            return h_sha512.hexdigest(), h_sha256.hexdigest(), (h_md5.hexdigest() if compute_md5 else "DISABLED")
        finally:
            os.close(fd)
    except Exception:
        return "N/A", "N/A", "N/A"

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

def main():
    if os.geteuid() != 0:
        print("[!] Critical Error: Root privileges required. Run with 'sudo'.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Professional Forensic Image Acquisition & Verification Suite")
    parser.add_argument("-s", "--source", required=True, help="Path to source device/file")
    parser.add_argument("-d", "--destination", required=True, help="Path to destination image file")
    parser.add_argument("-b", "--block-size", type=int, default=4096, help="Block size (Must be aligned to 512-byte sectors)")
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
    if args.block_size <= 0 or args.block_size > 1024 * 1024 * 16:
        print("[!] Critical Error: Block size must be between 1B and 16MB.")
        sys.exit(1)
    if args.block_size % 512 != 0:
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
        v_512, v_256, v_md5 = calculate_file_hashes(args.destination, args.block_size, compute_md5=args.legacy_md5)
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
        write_audit_and_custody_log(log_file_path, {
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

    source_size = get_device_size(args.source)
    dest_dir = os.path.dirname(os.path.abspath(args.destination)) or "."
    try:
        free_space = os.statvfs(dest_dir)
        available_bytes = free_space.f_bavail * free_space.f_frsize
        if source_size > 0 and available_bytes < source_size:
            print(f"[!] Critical Error: Insufficient space. Required: {source_size} B, Available: {available_bytes} B.")
            sys.exit(1)
    except Exception as e:
        print(f"[*] Warning: Direct storage allocation checks bypassed: {e}")

    # إصلاح التوصيف الجنائي لـ blockdev: هي مؤشر استشاري فقط (Advisory Only)
    is_write_blocked = get_device_ro_status(args.source)
    if not is_write_blocked:
        print(f"[!] Warning: Source write-block status: Advisory only. Kernel lock not detected!")
    else:
        print(f"[+] Source write-block status: Advisory locked via kernel flag.")
    
    offset = 0
    open_flags = os.O_WRONLY | os.O_CREAT

    hasher_src_512 = hashlib.sha512()
    hasher_src_256 = hashlib.sha256()
    hasher_src_md5 = hashlib.md5() if args.legacy_md5 else None

    # تحسين استقرار الذاكرة: إنشاء كائن الأصفار الثابت مرة واحدة لمنع الضغط والـ Garbage Collection المتكرر
    zero_padding = b'\x00' * args.block_size

    # 4. إصلاح حلقة الـ Pre-hashing وحمايتها من تسريبات واصف الملف (File Descriptor Leak Protection)
    if args.resume and os.path.exists(args.destination):
        offset = os.path.getsize(args.destination)
        if source_size > 0 and offset > source_size:
            print(f"[!] Resume Error: Target payload size exceeds logical source boundaries.")
            sys.exit(1)
        
        print(f"[*] Integrity Control: Computing pre-hash for existing destination stream ({offset} Bytes)...")
        existing_dest_sha512, _, _ = calculate_file_hashes(args.destination, args.block_size, compute_md5=False, limit_size=offset)
        
        print(f"[*] Integrity Control: Computing matching pre-hash for original source stream...")
        existing_src_sha512, _, _ = calculate_file_hashes(args.source, args.block_size, compute_md5=False, limit_size=offset)
        
        if existing_src_sha512 != existing_dest_sha512 or existing_src_sha512 == "N/A":
            print("[!] Forensic Integrity Failure: Historical destination segments do not align with source. Resume aborted.")
            sys.exit(1)
            
        # إغلاق وحصار حلقة القراءة داخل كتلة try/finally لمنع أي تسريب للـ File Descriptor نهائياً
        v_fd = os.open(args.source, os.O_RDONLY)
        try:
            bytes_to_feed = offset
            while bytes_to_feed > 0:
                try:
                    chunk = os.read(v_fd, min(args.block_size, bytes_to_feed))
                    if not chunk: break
                except OSError as err:
                    if err.errno == errno.EIO:
                        chunk = zero_padding[:min(args.block_size, bytes_to_feed)]
                        os.lseek(v_fd, (offset - bytes_to_feed) + len(chunk), os.SEEK_SET)
                    else:
                        raise
                hasher_src_512.update(chunk)
                hasher_src_256.update(chunk)
                if args.legacy_md5: hasher_src_md5.update(chunk)
                bytes_to_feed -= len(chunk)
        finally:
            os.close(v_fd)

        open_flags |= os.O_APPEND
        print(f"[+] Integrity baseline validated. Safely resuming acquisition from offset: {offset} B")
    else:
        open_flags |= os.O_TRUNC

    bad_sectors_map = []
    read_errors_detected = False
    last_progress_time = 0

    # 5. تشغيل المحرك وعزل الأخطاء الحقيقي (Strict Errno Filtering)
    print("[*] Initiating continuous stream mirroring pipeline...")
    try:
        src_fd = os.open(args.source, os.O_RDONLY)
        dest_fd = os.open(args.destination, open_flags, 0o666)
        
        try:
            if offset > 0:
                os.lseek(src_fd, offset, os.SEEK_SET)

            current_pos = offset
            while True:
                try:
                    chunk = os.read(src_fd, args.block_size)
                    if not chunk:
                        break
                    
                    hasher_src_512.update(chunk)
                    hasher_src_256.update(chunk)
                    if args.legacy_md5:
                        hasher_src_md5.update(chunk)
                    
                    write_pos = 0
                    while write_pos < len(chunk):
                        written = os.write(dest_fd, chunk[write_pos:])
                        if written == 0:
                            raise OSError(errno.ENOSPC, "Zero bytes written to target backend storage layer.")
                        write_pos += written
                        
                    current_pos += len(chunk)
                    
                except OSError as err:
                    # تصفية أخطاء النظام القاتلة لقطع العملية فوراً ومنع إنتاج أدلة مشوهة أو ناقصة
                    if err.errno in [errno.ENOSPC, errno.EACCES, errno.EPERM, errno.ENOMEM]:
                        print(f"\n[!] Critical System I/O Abort: {err.strerror} (Process Halted)")
                        sys.exit(1)
                    
                    # الفرز الجنائي الحصري للـ Bad Sector الفعلي (Input/Output Error)
                    if err.errno == errno.EIO:
                        print(f"\n[!] Physical Sector Read Failure logged at offset position: {current_pos}")
                        bad_sectors_map.append({'offset': current_pos, 'size': args.block_size, 'error': 'EIO - Hard Input/Output Read Error'})
                        read_errors_detected = True
                        
                        # استخدام مصفوفة البايتات الثابتة المخزنة مسبقاً (Memory Optimization)
                        w_pad = 0
                        while w_pad < len(zero_padding):
                            w_pad += os.write(dest_fd, zero_padding[w_pad:])
                            
                        current_pos += args.block_size
                        os.lseek(src_fd, current_pos, os.SEEK_SET)
                    else:
                        raise # تمرير الأخطاء غير المؤثرة على البنية التحتية مثل EINTR أو EBUSY ليتم معالجتها طبيعياً

                # مؤشر التقدم الذكي والسرعة والـ ETA
                current_time = time.time()
                if current_time - last_progress_time >= 0.5 and source_size > 0:
                    percent = (current_pos / source_size) * 100
                    elapsed = current_time - start_time
                    current_speed_bytes = current_pos / elapsed if elapsed > 0 else 0
                    current_speed_mb = current_speed_bytes / (1024 * 1024)
                    
                    remaining_bytes = source_size - current_pos
                    if current_speed_bytes > 0:
                        eta_seconds = int(remaining_bytes / current_speed_bytes)
                        eta_str = time.strftime('%H:%M:%S', time.gmtime(eta_seconds))
                    else:
                        eta_str = "--:--:--"
                        
                    print(f"\rProgress: {percent:.2f}% | Copied: {current_pos/(1024*1024):.1f} MB | Speed: {current_speed_mb:.2f} MB/s | ETA: {eta_str} ", end='', flush=True)
                    last_progress_time = current_time

            print(f"\rProgress: 100.00% | Copied: {current_pos/(1024*1024):.1f} MB | Synchronizing data storage buffers...")
            os.fsync(dest_fd) # دفع وحفظ البيانات فيزيائياً في نهاية المطاف للحفاظ على السرعة القصوى والأمان التام
            
        finally:
            os.close(src_fd)
            os.close(dest_fd)
            
    except Exception as e:
        print(f"\n[!] Critical Pipeline Failure during execution: {e}")
        sys.exit(1)

    duration = round(time.time() - start_time, 2)

    print("[+] Acquisition finalized. Calculating target verification footprints...")
    dest_sha512, dest_sha256, dest_md5 = calculate_file_hashes(args.destination, args.block_size, compute_md5=args.legacy_md5)
    
    # الالتزام التام بالفلسفة الجنائية المتقدمة للـ Hashes عند وجود تلف مادي
    if read_errors_detected:
        status_str = "COMPLETED WITH PHYSICAL SECTOR DEGRADATION (Target image structurally aligned via zero-padding)"
        src_sha512 = "INTEGRITY UNVERIFIABLE (Source hardware degradation prevents complete mathematical footprinting)"
        src_sha256 = "INTEGRITY UNVERIFIABLE"
        src_md5 = "INTEGRITY UNVERIFIABLE"
    else:
        src_sha512 = hasher_src_512.hexdigest()
        src_sha256 = hasher_src_256.hexdigest()
        src_md5 = hasher_src_md5.hexdigest() if args.legacy_md5 else "DISABLED"
        if src_sha512 == dest_sha512 and src_sha256 == dest_sha256:
            status_str = "SUCCESS - Hash Verification Passed"
        else:
            status_str = "FAILED - CRITICAL HASH MISMATCH DETECTED"

    print(f"[+] Status: {status_str}")

    try:
        copied_bytes = os.path.getsize(args.destination)
        acquisition_speed = round((copied_bytes / duration) / (1024 * 1024), 2) if duration > 0 else 0
    except Exception:
        copied_bytes = "Unknown"
        acquisition_speed = "Unknown"

    # تصدير سجل خريطة القطاعات المعطوبة المستقل للتقرير ولأدوات التحليل الرديفة
    if bad_sectors_map:
        csv_path = f"{args.destination}.bad_sectors.csv"
        try:
            with open(csv_path, mode='w', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=['offset', 'size', 'error'])
                writer.writeheader()
                writer.writerows(bad_sectors_map)
            print(f"[*] Sector structural mapping metadata exported to: {csv_path}")
        except Exception as e:
            print(f"[!] Warning: Failed to export map file log: {e}")

    # إنشاء التقرير الاستقصائي الفني الشامل للمحاكم والجهات الفنية العليا
    report_path = f"{args.destination}.report"
    try:
        with open(report_path, "w") as rep:
            rep.write("="*75 + "\n")
            rep.write("                         FORENSIC ACQUISITION REPORT\n")
            rep.write("="*75 + "\n")
            rep.write(f"Case Identifier String:   {args.case_number}\n")
            rep.write(f"Evidence Unit Identifier: {args.evidence_id}\n")
            rep.write(f"Active Forensic Examiner: {args.examiner}\n")
            rep.write("-" * 75 + "\n")
            rep.write(f"Platform Hostname Node:   {os.uname()[1]}\n")
            rep.write(f"Operating System Kernel:  {os.uname().sysname} {os.uname().release}\n")
            rep.write(f"Execution Start Window:   {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(start_time))}\n")
            rep.write(f"Execution End Window:     {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
            rep.write(f"Total Processing Time:    {duration} seconds\n")
            rep.write(f"Pipeline Running Velocity:{acquisition_speed} MB/s\n")
            rep.write(f"Sector Alignment Boundary:{args.block_size} Bytes\n")
            rep.write(f"Session Resume Flags:     {args.resume}\n")
            rep.write(f"Kernel Write-Block Status:{'Advisory Locked' if is_write_blocked else 'Advisory Unlocked / Warning'}\n")
            rep.write(f"Target Destination Image: {args.destination}\n")
            rep.write(f"Physical Acquired Bytes:  {copied_bytes} Bytes\n")
            rep.write(f"Pipeline Resolution State:{status_str}\n")
            rep.write(f"Defective Block Clusters: {len(bad_sectors_map)}\n")
            
            if read_errors_detected:
                rep.write("\nOFFICIAL FORENSIC DISCLOSURE AND MANDATE:\n")
                rep.write("  Physical input read degradation occurred during the acquisition phase. The destination\n")
                rep.write("  image file geometry was padded with zero-byte structures to enforce matching storage\n")
                rep.write("  alignment. The destination hashes provided below establish the unique mathematical\n")
                rep.write("  baseline for all derivative discovery and verification steps.\n")
            
            if bad_sectors_map:
                rep.write("-" * 75 + "\n")
                rep.write("                     DEFECTIVE HARDWARE SECTOR CLUSTER INDEX\n")
                for item in bad_sectors_map:
                    rep.write(f"Sector Bad Offset Location: {item['offset']} (Sector Block Size: {item['size']})\n")
                    
            rep.write("-"*75 + "\n")
            rep.write("                         CRYPTOGRAPHIC FOOTPRINT INDEX\n")
            rep.write(f"SHA-512 Destination Baseline: {dest_sha512}\n")
            rep.write(f"SHA-512 Source Reference:     {src_sha512}\n\n")
            rep.write(f"SHA-256 Destination Baseline: {dest_sha256}\n")
            rep.write(f"SHA-256 Source Reference:     {src_sha256}\n\n")
            rep.write(f"MD5 Destination (Legacy Mode):{dest_md5}\n")
            rep.write(f"MD5 Source Reference (Legacy):{src_md5}\n")
            rep.write("="*75 + "\n")

        print(f"[*] Investigative acquisition baseline report saved at: {report_path}")
    except Exception as e:
        print(f"[!] Failed to output final report file layout: {e}")

    # 6. حقن وتحديث السجل الرسمي لسلسلة الحيازة لتوثيق نقل العهدة والموثوقية القانونية بالكامل
    write_audit_and_custody_log(log_file_path, {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        "action": f"Physical Acquisition Session (Resume Mode: {args.resume}, Status: {status_str})",
        "case_number": args.case_number, "evidence_id": args.evidence_id,
        "released_by": args.released_by, "examiner": args.examiner, "purpose": args.purpose,
        "destination": args.destination, "sha512": dest_sha512
    })

    del hasher_src_512, hasher_src_256, hasher_src_md5

if __name__ == "__main__":
    main()
