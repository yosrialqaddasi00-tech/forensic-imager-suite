"""Core acquisition engine: streaming copy, bad-sector handling, and resume.

Encapsulates the bit-stream mirroring pipeline that was previously inline in main().
The CLI is responsible for device probing and report/custody generation; this module
owns the read/write loop, physical sector degradation mitigation, and the integrity
baseline validation used when resuming an interrupted acquisition.
"""
import os
import sys
import time
import errno
import csv
import hashlib

from . import hashing


class BadSector:
    """A single physically defective sector encountered during acquisition."""

    def __init__(self, offset, size, error):
        self.offset = offset
        self.size = size
        self.error = error


class AcquisitionResult:
    """Outcome of a completed (or aborted) acquisition run."""

    def __init__(self):
        self.status_str = ""
        self.dest_sha512 = self.dest_sha256 = self.dest_md5 = ""
        self.src_sha512 = self.src_sha256 = self.src_md5 = ""
        self.copied_bytes = 0
        self.duration = 0.0
        self.acquisition_speed = 0.0
        self.bad_sectors_map = []
        self.read_errors_detected = False
        self.offset = 0
        self.is_write_blocked = False


def run_acquisition(source, destination, block_size, resume, compute_md5,
                    start_time, source_size, is_write_blocked):
    """Stream `source` into `destination`, returning an AcquisitionResult.

    Mirrors the original inline pipeline exactly: incremental hashing, EIO
    zero-padding for bad sectors, ENOSPC/EPERM abort, progress printing, fsync,
    and (when `resume` is set and the destination exists) the pre-hash integrity
    baseline check before continuing from the existing offset.
    """
    result = AcquisitionResult()
    result.is_write_blocked = is_write_blocked

    offset = 0
    open_flags = os.O_WRONLY | os.O_CREAT

    hasher_src_512 = hashlib.sha512()
    hasher_src_256 = hashlib.sha256()
    hasher_src_md5 = hashlib.md5() if compute_md5 else None

    # تحسين استقرار الذاكرة: إنشاء كائن الأصفار الثابت مرة واحدة لمنع الضغط والـ Garbage Collection المتكرر
    zero_padding = b'\x00' * block_size

    # 4. إصلاح حلقة الـ Pre-hashing وحمايتها من تسريبات واصف الملف (File Descriptor Leak Protection)
    if resume and os.path.exists(destination):
        offset = os.path.getsize(destination)
        if source_size > 0 and offset > source_size:
            print(f"[!] Resume Error: Target payload size exceeds logical source boundaries.")
            sys.exit(1)

        print(f"[*] Integrity Control: Computing pre-hash for existing destination stream ({offset} Bytes)...")
        existing_dest = hashing.calculate_file_hashes(destination, block_size, compute_md5=False, limit_size=offset)
        existing_dest_sha512 = existing_dest.sha512

        print(f"[*] Integrity Control: Computing matching pre-hash for original source stream...")
        existing_src = hashing.calculate_file_hashes(source, block_size, compute_md5=False, limit_size=offset)
        existing_src_sha512 = existing_src.sha512

        if existing_src_sha512 != existing_dest_sha512 or existing_src_sha512 == "N/A":
            print("[!] Forensic Integrity Failure: Historical destination segments do not align with source. Resume aborted.")
            sys.exit(1)

        # إغلاق وحصار حلقة القراءة داخل كتلة try/finally لمنع أي تسريب للـ File Descriptor نهائياً
        v_fd = os.open(source, os.O_RDONLY)
        try:
            bytes_to_feed = offset
            while bytes_to_feed > 0:
                try:
                    chunk = os.read(v_fd, min(block_size, bytes_to_feed))
                    if not chunk: break
                except OSError as err:
                    if err.errno == errno.EIO:
                        chunk = zero_padding[:min(block_size, bytes_to_feed)]
                        os.lseek(v_fd, (offset - bytes_to_feed) + len(chunk), os.SEEK_SET)
                    else:
                        raise
                hasher_src_512.update(chunk)
                hasher_src_256.update(chunk)
                if compute_md5: hasher_src_md5.update(chunk)
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
        src_fd = os.open(source, os.O_RDONLY)
        dest_fd = os.open(destination, open_flags, 0o666)

        try:
            if offset > 0:
                os.lseek(src_fd, offset, os.SEEK_SET)

            current_pos = offset
            while True:
                try:
                    chunk = os.read(src_fd, block_size)
                    if not chunk:
                        break

                    hasher_src_512.update(chunk)
                    hasher_src_256.update(chunk)
                    if compute_md5:
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
                        bad_sectors_map.append({'offset': current_pos, 'size': block_size, 'error': 'EIO - Hard Input/Output Read Error'})
                        read_errors_detected = True

                        # استخدام مصفوفة البايتات الثابتة المخزنة مسبقاً (Memory Optimization)
                        w_pad = 0
                        while w_pad < len(zero_padding):
                            w_pad += os.write(dest_fd, zero_padding[w_pad:])

                        current_pos += block_size
                        os.lseek(src_fd, current_pos, os.SEEK_SET)
                    else:
                        raise  # تمرير الأخطاء غير المؤثرة على البنية التحتية مثل EINTR أو EBUSY ليتم معالجتها طبيعياً

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

            print(f"\rProgress: 100.00% | Copied: {current_pos/(1024*1024):.1f} MB | Synchronizing data storage buffers...")
            os.fsync(dest_fd)  # دفع وحفظ البيانات فيزيائياً في نهاية المطاف للحفاظ على السرعة القصوى والأمان التام

        finally:
            os.close(src_fd)
            os.close(dest_fd)

    except Exception as e:
        print(f"\n[!] Critical Pipeline Failure during execution: {e}")
        sys.exit(1)

    duration = round(time.time() - start_time, 2)

    print("[+] Acquisition finalized. Calculating target verification footprints...")
    dest = hashing.calculate_file_hashes(destination, block_size, compute_md5=compute_md5)
    dest_sha512, dest_sha256, dest_md5 = dest.sha512, dest.sha256, dest.md5

    # الالتزام التام بالفلسفة الجنائية المتقدمة للـ Hashes عند وجود تلف مادي
    if read_errors_detected:
        status_str = "COMPLETED WITH PHYSICAL SECTOR DEGRADATION (Target image structurally aligned via zero-padding)"
        src_sha512 = "INTEGRITY UNVERIFIABLE (Source hardware degradation prevents complete mathematical footprinting)"
        src_sha256 = "INTEGRITY UNVERIFIABLE"
        src_md5 = "INTEGRITY UNVERIFIABLE"
    else:
        src_sha512 = hasher_src_512.hexdigest()
        src_sha256 = hasher_src_256.hexdigest()
        src_md5 = hasher_src_md5.hexdigest() if compute_md5 else "DISABLED"
        if src_sha512 == dest_sha512 and src_sha256 == dest_sha256:
            status_str = "SUCCESS - Hash Verification Passed"
        else:
            status_str = "FAILED - CRITICAL HASH MISMATCH DETECTED"

    print(f"[+] Status: {status_str}")

    try:
        copied_bytes = os.path.getsize(destination)
        acquisition_speed = round((copied_bytes / duration) / (1024 * 1024), 2) if duration > 0 else 0
    except Exception:
        copied_bytes = "Unknown"
        acquisition_speed = "Unknown"

    # تصدير سجل خريطة القطاعات المعطوبة المستقل للتقرير ولأدوات التحليل الرديفة
    if bad_sectors_map:
        csv_path = f"{destination}.bad_sectors.csv"
        try:
            with open(csv_path, mode='w', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=['offset', 'size', 'error'])
                writer.writeheader()
                writer.writerows(bad_sectors_map)
            print(f"[*] Sector structural mapping metadata exported to: {csv_path}")
        except Exception as e:
            print(f"[!] Warning: Failed to export map file log: {e}")

    result.status_str = status_str
    result.dest_sha512 = dest_sha512
    result.dest_sha256 = dest_sha256
    result.dest_md5 = dest_md5
    result.src_sha512 = src_sha512
    result.src_sha256 = src_sha256
    result.src_md5 = src_md5
    result.copied_bytes = copied_bytes
    result.duration = duration
    result.acquisition_speed = acquisition_speed
    result.bad_sectors_map = bad_sectors_map
    result.read_errors_detected = read_errors_detected
    result.offset = offset
    return result
