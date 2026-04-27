import json
import time
import os
from datetime import datetime


class LogMonitor:
    """
    Continuously tails the Nginx JSON access log
    and parses each line into structured data.
    """

    def __init__(self, config, data_store):
        # path to the nginx log file from config
        self.log_path = config['log']['nginx_access_log']
        self.data_store = data_store

    def parse_line(self, line):
        """
        Parse a single JSON log line into a dictionary.
        Returns None if the line is invalid.
        """
        line = line.strip()
        if not line:
            return None
        try:
            entry = json.loads(line)
            # extract all required fields
            return {
                'source_ip':     entry.get('source_ip', ''),
                'timestamp':     entry.get('timestamp', ''),
                'method':        entry.get('method', ''),
                'path':          entry.get('path', ''),
                'status':        int(entry.get('status', 0)),
                'response_size': int(entry.get('response_size', 0)),
                'parsed_at':     datetime.utcnow()
            }
        except (json.JSONDecodeError, ValueError):
            # skip malformed lines
            return None

    def tail(self):
        """
        Continuously tail the log file line by line.
        Waits for the file to exist if it doesn't yet.
        Yields parsed log entries one at a time.
        """
        # wait for log file to exist
        while not os.path.exists(self.log_path):
            print(f"[Monitor] Waiting for log file: {self.log_path}")
            time.sleep(2)

        print(f"[Monitor] Tailing log file: {self.log_path}")

        with open(self.log_path, 'r') as f:
            # move to end of file so we only read new lines
            f.seek(0, 2)

            while True:
                line = f.readline()
                if not line:
                    # no new line yet — wait a moment and try again
                    time.sleep(0.1)
                    continue

                entry = self.parse_line(line)
                if entry:
                    # push parsed entry into shared data store
                    self.data_store.add_request(entry)
                    yield entry
