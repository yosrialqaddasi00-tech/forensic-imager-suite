"""Cryptographic hashing for forensic acquisition and verification.

Hashes are computed incrementally while reading the source/destination stream. A
physical read error (errno.EIO) is tolerated by substituting a zero-filled chunk so
that the mathematical footprint can still be produced for comparison purposes.
"""
import os
import errno
import hashlib
from dataclasses import dataclass

from .constants import DEFAULT_BLOCK_SIZE


@dataclass
class HashResult:
    sha512: str
    sha256: str
    md5: str  # "DISABLED" when MD5 was not requested, "N/A" on read failure


def calculate_file_hashes(file_path, block_size=DEFAULT_BLOCK_SIZE, compute_md5=False, limit_size=None):
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

            return HashResult(
                sha512=h_sha512.hexdigest(),
                sha256=h_sha256.hexdigest(),
                md5=h_md5.hexdigest() if compute_md5 else "DISABLED",
            )
        finally:
            os.close(fd)
    except Exception:
        return HashResult(sha512="N/A", sha256="N/A", md5="N/A")
