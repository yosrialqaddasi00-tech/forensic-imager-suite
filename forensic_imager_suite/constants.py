# Forensic Imager Suite — shared constants
#
# Centralized so the geometry/limit magic numbers used across the engine live in
# one place instead of being repeated inline.

SECTOR_SIZE = 512                       # physical sector alignment boundary
DEFAULT_BLOCK_SIZE = 4096               # default read/write block size
MIN_BLOCK_SIZE = 1                      # smallest allowed block size (1 byte)
MAX_BLOCK_SIZE = 16 * 1024 * 1024       # largest allowed block size (16 MB)
