import datetime
import os
from utils import hide_file, get_log_path

class HiddenLogger:
    def __init__(self):
        self.log_path = get_log_path()
        # Initialize file if it doesn't exist
        if not os.path.exists(self.log_path):
            with open(self.log_path, "w") as f:
                f.write(f"--- Sentry Log Initialized: {datetime.datetime.now()} ---\n")
            hide_file(self.log_path)

    def log_event(self, event_type, what, where, entry_point):
        """
        Logs a security event with descriptive fields.
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = (
            f"[{timestamp}] EVENT: {event_type} | "
            f"WHAT: {what} | "
            f"WHERE: {where} | "
            f"ENTRY_POINT: {entry_point}\n"
        )
        
        with open(self.log_path, "a") as f:
            f.write(entry)
        
        # Re-verify hidden attribute on Windows just in case
        hide_file(self.log_path)

if __name__ == "__main__":
    logger = HiddenLogger()
    logger.log_event("TEST", "Initial log test", "/system/test", "Local Console")
    print(f"Log updated at {logger.log_path}")
