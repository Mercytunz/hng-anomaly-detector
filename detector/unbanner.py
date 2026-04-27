import time
import threading
from datetime import datetime, timedelta


class Unbanner:
    """
    Monitors active bans and releases them
    according to the backoff schedule.
    Sends Slack notification on every unban.
    """

    def __init__(self, config, blocker, notifier,
                 detector, audit_logger):
        self.blocker      = blocker
        self.notifier     = notifier
        self.detector     = detector
        self.audit_logger = audit_logger

        # check for expired bans every 30 seconds
        self.check_interval = 30

    def run(self):
        """
        Background thread — checks for expired bans
        every 30 seconds forever.
        """
        print("[Unbanner] Started — monitoring active bans")
        while True:
            time.sleep(self.check_interval)
            self._check_bans()

    def _check_bans(self):
        """
        Loop through all active bans and release
        any that have expired.
        """
        now = datetime.utcnow()
        active_bans = self.blocker.get_active_bans()

        for ip, ban_info in active_bans.items():
            duration = ban_info['duration']

            # skip permanent bans — duration = -1
            if duration == -1:
                continue

            banned_at  = ban_info['banned_at']
            ban_number = ban_info['ban_number']

            # calculate when ban expires
            expires_at = banned_at + timedelta(minutes=duration)

            if now >= expires_at:
                self._release_ban(ip, ban_info)

    def _release_ban(self, ip, ban_info):
        """
        Release a ban — remove iptables rule,
        notify Slack, write audit log.
        """
        duration   = ban_info['duration']
        ban_number = ban_info['ban_number']

        print(
            f"[Unbanner] Releasing ban for {ip} "
            f"after {duration} minutes "
            f"(ban #{ban_number})"
        )

        # remove iptables rule
        self.blocker.unban(ip)

        # tell detector this IP is no longer banned
        self.detector.unban_ip(ip)

        # get next ban duration for Slack message
        backoff    = self.blocker.backoff_schedule
        next_index = ban_number  # ban_number is already incremented
        if next_index < len(backoff):
            next_duration = backoff[next_index]
            next_str = (
                f"{next_duration} min"
                if next_duration != -1
                else "permanent"
            )
        else:
            next_str = "permanent"

        # send Slack unban notification
        self.notifier.send_unban_alert(
            ip=ip,
            duration=duration,
            ban_number=ban_number,
            next_ban_duration=next_str
        )

        # write audit log
        self.audit_logger.log_unban(
            ip=ip,
            duration=duration,
            ban_number=ban_number
        )
