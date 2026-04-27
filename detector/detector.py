import time
import threading
from collections import deque, defaultdict
from datetime import datetime


class AnomalyDetector:
    """
    Detects anomalies using two deque-based sliding windows
    — one per IP, one global — over the last 60 seconds.
    Fires if z-score > 3.0 or rate > 5x baseline mean.
    """

    def __init__(self, config, baseline, blocker, notifier, audit_logger):
        cfg = config['detection']
        win = config['windows']

        # thresholds from config
        self.zscore_threshold      = cfg['zscore_threshold']
        self.rate_multiplier       = cfg['rate_multiplier']
        self.error_rate_multiplier = cfg['error_rate_multiplier']

        # window sizes in seconds
        self.per_ip_seconds  = win['per_ip_seconds']
        self.global_seconds  = win['global_seconds']

        # dependencies
        self.baseline     = baseline
        self.blocker      = blocker
        self.notifier     = notifier
        self.audit_logger = audit_logger

        # per-IP sliding window
        # key = ip, value = deque of timestamps
        self.ip_windows = defaultdict(deque)

        # per-IP error sliding window
        # key = ip, value = deque of timestamps
        self.ip_error_windows = defaultdict(deque)

        # global sliding window — deque of timestamps
        self.global_window = deque()

        # track already banned IPs to avoid duplicate bans
        self.banned_ips = set()

        # thread lock
        self.lock = threading.Lock()

    def _evict_old(self, window, cutoff):
        """
        Remove timestamps older than cutoff from
        the left side of the deque.
        """
        while window and window[0] < cutoff:
            window.popleft()

    def record(self, entry):
        """
        Record a new request and check for anomalies.
        Called for every parsed log entry.
        """
        now       = time.time()
        ip        = entry['source_ip']
        status    = entry['status']

        with self.lock:
            # --- update global window ---
            cutoff_global = now - self.global_seconds
            self._evict_old(self.global_window, cutoff_global)
            self.global_window.append(now)

            # --- update per-IP window ---
            cutoff_ip = now - self.per_ip_seconds
            self._evict_old(self.ip_windows[ip], cutoff_ip)
            self.ip_windows[ip].append(now)

            # --- update per-IP error window ---
            if status >= 400:
                self._evict_old(
                    self.ip_error_windows[ip], cutoff_ip
                )
                self.ip_error_windows[ip].append(now)

            # get current rates
            global_rate = len(self.global_window)
            ip_rate     = len(self.ip_windows[ip])
            error_rate  = len(self.ip_error_windows[ip])

            # get baseline stats
            mean, stddev = self.baseline.get_stats()

            # check error surge — tighten threshold for this IP
            error_threshold = self.zscore_threshold
            if error_rate >= (mean * self.error_rate_multiplier):
                # tighten z-score threshold for this IP
                error_threshold = self.zscore_threshold * 0.5

            # --- check per-IP anomaly ---
            if ip not in self.banned_ips:
                ip_zscore = (ip_rate - mean) / stddev
                if (ip_zscore > error_threshold or
                        ip_rate > mean * self.rate_multiplier):
                    self._handle_ip_anomaly(
                        ip, ip_rate, ip_zscore, mean
                    )

            # --- check global anomaly ---
            global_zscore = (global_rate - mean) / stddev
            if (global_zscore > self.zscore_threshold or
                    global_rate > mean * self.rate_multiplier):
                self._handle_global_anomaly(
                    global_rate, global_zscore, mean
                )

    def _handle_ip_anomaly(self, ip, rate, zscore, mean):
        """
        Handle a per-IP anomaly — ban the IP and alert.
        """
        print(
            f"[Detector] IP anomaly detected: {ip} "
            f"rate={rate} zscore={zscore:.2f} mean={mean:.2f}"
        )

        # mark as banned
        self.banned_ips.add(ip)

        # block the IP
        duration = self.blocker.ban(ip)

        # send Slack alert
        self.notifier.send_ban_alert(
            ip=ip,
            rate=rate,
            zscore=zscore,
            baseline_mean=mean,
            duration=duration
        )

        # write audit log
        self.audit_logger.log_ban(
            ip=ip,
            condition=f"zscore={zscore:.2f} rate={rate}",
            rate=rate,
            baseline=mean,
            duration=duration
        )

    def _handle_global_anomaly(self, rate, zscore, mean):
        """
        Handle a global anomaly — Slack alert only, no ban.
        """
        print(
            f"[Detector] Global anomaly detected: "
            f"rate={rate} zscore={zscore:.2f} mean={mean:.2f}"
        )

        # send Slack alert only — no IP to ban
        self.notifier.send_global_alert(
            rate=rate,
            zscore=zscore,
            baseline_mean=mean
        )

    def unban_ip(self, ip):
        """Called by unbanner when a ban is lifted."""
        with self.lock:
            self.banned_ips.discard(ip)

    def get_top_ips(self, n=10):
        """Return top N IPs by request count in current window."""
        with self.lock:
            now = time.time()
            cutoff = now - self.per_ip_seconds
            counts = {}
            for ip, window in self.ip_windows.items():
                self._evict_old(window, cutoff)
                if window:
                    counts[ip] = len(window)
            sorted_ips = sorted(
                counts.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ips[:n]

    def get_global_rate(self):
        """Return current global request rate."""
        with self.lock:
            now = time.time()
            cutoff = now - self.global_seconds
            self._evict_old(self.global_window, cutoff)
            return len(self.global_window)
