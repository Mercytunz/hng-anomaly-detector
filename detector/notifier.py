import requests
import threading
from datetime import datetime


class Notifier:
    """
    Sends Slack alerts for bans, unbans,
    and global anomaly events.
    """

    def __init__(self, config):
        self.webhook_url = config['slack']['webhook_url']
        # thread lock to avoid overlapping Slack calls
        self.lock = threading.Lock()

    def _send(self, message):
        """
        Send a message to Slack via webhook.
        """
        with self.lock:
            try:
                response = requests.post(
                    self.webhook_url,
                    json={'text': message},
                    timeout=5
                )
                if response.status_code != 200:
                    print(
                        f"[Notifier] Slack error: "
                        f"{response.status_code} {response.text}"
                    )
            except requests.RequestException as e:
                print(f"[Notifier] Failed to send Slack alert: {e}")

    def send_ban_alert(self, ip, rate, zscore,
                       baseline_mean, duration):
        """
        Send a Slack alert when an IP is banned.
        """
        duration_str = (
            f"{duration} minutes"
            if duration != -1
            else "PERMANENT"
        )

        message = (
            f":rotating_light: *IP BANNED*\n"
            f">*IP:* `{ip}`\n"
            f">*Condition:* z-score={zscore:.2f} | "
            f"rate={rate} req/s\n"
            f">*Baseline Mean:* {baseline_mean:.2f} req/s\n"
            f">*Ban Duration:* {duration_str}\n"
            f">*Timestamp:* {datetime.utcnow().isoformat()}Z"
        )

        print(f"[Notifier] Sending ban alert for {ip}")
        self._send(message)

    def send_unban_alert(self, ip, duration,
                         ban_number, next_ban_duration):
        """
        Send a Slack alert when an IP ban is lifted.
        """
        message = (
            f":white_check_mark: *IP UNBANNED*\n"
            f">*IP:* `{ip}`\n"
            f">*Ban #{ban_number} expired after:* "
            f"{duration} minutes\n"
            f">*Next ban duration if reoffends:* "
            f"{next_ban_duration}\n"
            f">*Timestamp:* {datetime.utcnow().isoformat()}Z"
        )

        print(f"[Notifier] Sending unban alert for {ip}")
        self._send(message)

    def send_global_alert(self, rate, zscore, baseline_mean):
        """
        Send a Slack alert for a global traffic anomaly.
        No IP ban — just an alert.
        """
        message = (
            f":warning: *GLOBAL ANOMALY DETECTED*\n"
            f">*Global Rate:* {rate} req/s\n"
            f">*Z-Score:* {zscore:.2f}\n"
            f">*Baseline Mean:* {baseline_mean:.2f} req/s\n"
            f">*Action:* No single IP blocked — "
            f"global traffic spike\n"
            f">*Timestamp:* {datetime.utcnow().isoformat()}Z"
        )

        print("[Notifier] Sending global anomaly alert")
        self._send(message)
