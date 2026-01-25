
import logging
import logging.handlers
import os
import time
import glob
from datetime import datetime

class DailyRotatingFileHandler(logging.FileHandler):
    """
    Handler that writes to a file named with the current date,
    and rotates to a new file at midnight.
    Format: prefix-YYYY-MM-DD.log
    """
    def __init__(self, log_directory, filename_prefix, retention_days=7, encoding='utf-8'):
        self.log_directory = log_directory
        self.filename_prefix = filename_prefix
        self.retention_days = retention_days
        self.current_date = datetime.utcnow().date()
        
        filename = self._get_filename(self.current_date)
        os.makedirs(log_directory, exist_ok=True)
        
        super().__init__(filename, encoding=encoding)
        
    def _get_filename(self, date_obj):
        return os.path.join(
            self.log_directory, 
            f"{self.filename_prefix}-{date_obj.strftime('%Y-%m-%d')}.log"
        )

    def emit(self, record):
        # Check if date has changed
        new_date = datetime.utcnow().date()
        if new_date != self.current_date:
            self.current_date = new_date
            self._rotate()
        
        super().emit(record)

    def _rotate(self):
        # Close current file
        self.close()
        
        # Open new file
        self.baseFilename = self._get_filename(self.current_date)
        self.stream = self._open()
        
        # Clean up old logs
        self._cleanup()

    def _cleanup(self):
        try:
            pattern = os.path.join(self.log_directory, f"{self.filename_prefix}-*.log")
            files = glob.glob(pattern)
            files.sort()
            
            if len(files) > self.retention_days:
                to_delete = files[:-self.retention_days]
                for f in to_delete:
                    try:
                        os.remove(f)
                    except OSError:
                        pass
        except Exception:
            pass
