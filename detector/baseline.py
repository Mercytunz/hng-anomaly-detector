import time
import threading
from collections import deque
from datetime import datetime
import math


class BaselineTracker:
    """
    Tracks normal traffic patterns using a rolling
    30-minute window of per-second request counts.
    Recalculates mean and stddev every 60 seconds.
    Maintains per-hour slots to prefer current hour data.
    """

    def __init__(self, config):
        cfg = config['baseline']

        # how many minutes to keep in rolling window
        self.window_minutes = cfg['window_minutes']

        # how often to recalculate in seconds
        self.recalculate_every = cfg['recalculate_every']

        # minimum requests before we trust the baseline
        self.min_requests = cfg['min_requests']

        # floor values to avoid division by zero
        self.floor_mean   = cfg['floor_mean']
        self.floor_stddev = cfg['floor_stddev']

        # rolling window — stores per-second request counts
        # max size = 30 minutes * 60 seconds = 1800 slots
        maxlen = self.window_minutes * 60
        self.per_second_counts = deque(maxlen=maxlen)

        # per-hour slots — key is hour (0-23), value is list of counts
        self.hourly_slots = {}

        # current calculated baseline values
        self.effective_mean   = self.floor_mean
        self.effective_stddev = self.floor_stddev

        # baseline for error rates
        self.error_mean   = self.floor_mean
        self.error_stddev = self.floor_stddev

        # counts for current second
        self.current_second_count = 0
        self.current_second_errors = 0
        self.current_second = int(time.time())

        # thread lock for safe access
        self.lock = threading.Lock()

        # history of baseline values for graphing
        self.baseline_history = deque(maxlen=200)

    def record_request(self, status_code):
        """
        Called for every incoming request.
        Buckets requests into per-second counts.
        """
        now = int(time.time())
        with self.lock:
            if now != self.current_second:
                # new second — save previous second's count
                self._flush_second()
                self.current_second = now
                self.current_second_count = 0
                self.current_second_errors = 0

            self.current_second_count += 1

            # track error requests (4xx and 5xx)
            if status_code >= 400:
                self.current_second_errors += 1

    def _flush_second(self):
        """
        Save the completed second's count into
        the rolling window and hourly slots.
        """
        count = self.current_second_count
        errors = self.current_second_errors
        hour = datetime.utcnow().hour

        # add to rolling window
        self.per_second_counts.append(count)

        # add to hourly slot
        if hour not in self.hourly_slots:
            self.hourly_slots[hour] = deque(maxlen=3600)
        self.hourly_slots[hour].append(count)

    def _calculate_stats(self, data):
        """
        Calculate mean and standard deviation
        from a list of numbers.
        """
        if not data or len(data) < 2:
            return self.floor_mean, self.floor_stddev

        n = len(data)
        mean = sum(data) / n

        # calculate standard deviation
        variance = sum((x - mean) ** 2 for x in data) / n
        stddev = math.sqrt(variance)

        # apply floor values
        mean   = max(mean, self.floor_mean)
        stddev = max(stddev, self.floor_stddev)

        return mean, stddev

    def recalculate(self):
        """
        Recalculate the effective mean and stddev.
        Prefers current hour data if enough exists,
        otherwise falls back to full rolling window.
        """
        with self.lock:
            current_hour = datetime.utcnow().hour
            hourly_data = list(
                self.hourly_slots.get(current_hour, [])
            )

            # prefer current hour if it has enough data
            if len(hourly_data) >= self.min_requests:
                data = hourly_data
                source = f"hour-{current_hour}"
            else:
                data = list(self.per_second_counts)
                source = "rolling-window"

            self.effective_mean, self.effective_stddev = \
                self._calculate_stats(data)

            # record history for baseline graph
            self.baseline_history.append({
                'timestamp':  datetime.utcnow().isoformat(),
                'mean':       self.effective_mean,
                'stddev':     self.effective_stddev,
                'source':     source,
                'data_points': len(data)
            })

            return self.effective_mean, self.effective_stddev

    def run(self, audit_logger):
        """
        Background thread — recalculates baseline
        every 60 seconds forever.
        """
        while True:
            time.sleep(self.recalculate_every)
            mean, stddev = self.recalculate()

            # write to audit log
            audit_logger.log_baseline(mean, stddev)
            print(
                f"[Baseline] Recalculated — "
                f"mean={mean:.2f} stddev={stddev:.2f}"
            )

    def get_stats(self):
        """Return current baseline stats."""
        return self.effective_mean, self.effective_stddev
