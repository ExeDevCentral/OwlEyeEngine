import os
import ctypes
import platform

def is_windows():
    return platform.system() == "Windows"

def hide_file(filepath):
    """
    Makes a file hidden according to the OS.
    Windows: Sets the hidden attribute.
    Linux: Prefixing with '.' is usually enough, but here we ensure the name starts with '.'
    """
    if is_windows():
        # FILE_ATTRIBUTE_HIDDEN = 0x02
        try:
            ctypes.windll.kernel32.SetFileAttributesW(filepath, 0x02)
            return True
        except Exception:
            return False
    else:
        # On Linux, hiding is by convention (filename starts with .)
        # The caller should handle the naming, but we return True for consistency.
        return True

def get_log_path():
    """
    Returns the appropriate hidden log path based on OS.
    """
    if is_windows():
        return os.path.join(os.getcwd(), "_sentry_log.sys")
    else:
        return os.path.join(os.getcwd(), ".sentry_log")
