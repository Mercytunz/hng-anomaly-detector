import threading
import yaml
import os
import sys
from datetime import datetime

from monitor   import LogMonitor
from baseline  import BaselineTracker
from detector  import AnomalyDetector
from blocker   import Blocker
from unbanner  import Unbanner
from notifier  import Notifier
from dashboard import Dashboard


# ── Audit Logger ─────────────────────────────────────────────
class AuditLogger:
    """
    Writes structured log entries for every ban,
    unban, and baseline recalculation event.
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, log_path):
        self.log_path = log_path
        # create log directory if it doesn't exist
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def _write(self, line):
        with open(self.log_path, 'a') as f:
            f.write(line + '\n')
        print(line)

    def log_ban(self, ip, condition, rate, baseline, duration):
        duration_str = (
            f"{duration}min" if duration != -1
            else "permanent"
        )
        line = (
            f"[{datetime.utcnow().isoformat()}] BAN "
            f"{ip} | {condition} | "
            f"rate={rate} | baseline={baseline:.2f} | "
            f"duration={duration_str}"
        )
        self._write(line)

    def log_unban(self, ip, duration, ban_number):
        line = (
            f"[{datetime.utcnow().isoformat()}] UNBAN "
            f"{ip} | ban_number={ban_number} | "
            f"duration={duration}min"
        )
        self._write(line)

    def log_baseline(self, mean, stddev):
        line = (
            f"[{datetime.utcnow().isoformat()}] BASELINE "
            f"recalculated | "
            f"mean={mean:.2f} | stddev={stddev:.2f}"
        )
        self._write(line)


# ── Data Store ────────────────────────────────────────────────
class DataStore:
    """
    Shared data store that receives parsed log
    entries from monitor and passes them to
    baseline and detector.
    """

    def __init__(self, baseline, detector):
        self.baseline = baseline
        self.detector = detector

    def add_request(self, entry):
        # feed into baseline tracker
        self.baseline.record_request(entry['status'])
        # feed into anomaly detector
        self.detector.record(entry)


# ── Main ──────────────────────────────────────────────────────
def main():
    print("[Main] Starting HNG Anomaly Detector...")

    # load config
    config_path = os.path.join(
        os.path.dirname(__file__), 'config.yaml'
    )
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    # override webhook URL from environment variable if set
    slack_webhook = os.environ.get('SLACK_WEBHOOK_URL')
    if slack_webhook:
        config['slack']['webhook_url'] = slack_webhook
        print("[Main] Slack webhook loaded from environment")

    print("[Main] Config loaded")

    # initialise audit logger
    audit_logger = AuditLogger(config['log']['audit_log'])

    # initialise components
    notifier  = Notifier(config)
    blocker   = Blocker(config)
    baseline  = BaselineTracker(config)

    # detector needs blocker and notifier
    detector  = AnomalyDetector(
        config, baseline, blocker,
        notifier, audit_logger
    )

    # unbanner needs blocker, notifier, detector
    unbanner  = Unbanner(
        config, blocker, notifier,
        detector, audit_logger
    )

    # data store connects monitor → baseline + detector
    data_store = DataStore(baseline, detector)

    # monitor reads logs and feeds data store
    monitor   = LogMonitor(config, data_store)

    # dashboard displays everything
    dashboard = Dashboard(
        config, blocker, detector, baseline
    )

    print("[Main] All components initialised")

    # ── Start background threads ──────────────────────────────

    # baseline recalculation thread
    baseline_thread = threading.Thread(
        target=baseline.run,
        args=(audit_logger,),
        daemon=True,
        name="BaselineThread"
    )

    # unbanner thread
    unbanner_thread = threading.Thread(
        target=unbanner.run,
        daemon=True,
        name="UnbannerThread"
    )

    # dashboard thread
    dashboard_thread = threading.Thread(
        target=dashboard.run,
        daemon=True,
        name="DashboardThread"
    )

    # start all threads
    baseline_thread.start()
    unbanner_thread.start()
    dashboard_thread.start()

    print("[Main] All threads started")
    print(
        f"[Main] Dashboard available at "
        f"http://0.0.0.0:{config['dashboard']['port']}"
    )
    print("[Main] Monitoring traffic... (Ctrl+C to stop)")

    # ── Main loop — tail log and process entries ──────────────
    try:
        for entry in monitor.tail():
            # entry is already processed by data_store
            # inside monitor via data_store.add_request()
            pass
    except KeyboardInterrupt:
        print("\n[Main] Shutting down gracefully...")
        sys.exit(0)


if __name__ == '__main__':
    main()
