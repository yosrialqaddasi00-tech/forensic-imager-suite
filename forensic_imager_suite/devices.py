"""Device probing helpers: physical size, write-block status, free space.

Wraps the advisory `blockdev` queries and the filesystem statvfs free-space check
that the engine uses to validate an acquisition before streaming begins.
"""
import os
import subprocess


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


def get_available_space(path):
    """Return the number of available bytes on the filesystem holding `path`."""
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize
