import subprocess
import threading
from datetime import datetime


class Blocker:
    """
    Blocks IPs using iptables DROP rules.
    Tracks ban counts per IP for backoff scheduling.
    Must execute within 10 seconds of detection.
    """

    def __init__(self, config):
        # backoff schedule in minutes from config
        self.backoff_schedule = config['backoff']

        # track how many times each IP has been banned
        # key = ip, value = ban count (0-indexed)
        self.ban_counts = {}

        # currently banned IPs and their details
        # key = ip, value = {banned_at, duration, ban_number}
        self.active_bans = {}

        # thread lock
        self.lock = threading.Lock()

    def ban(self, ip):
        """
        Add an iptables DROP rule for the given IP.
        Returns the ban duration in minutes.
        """
        with self.lock:
            # get how many times this IP has been banned before
            ban_number = self.ban_counts.get(ip, 0)

            # get duration from backoff schedule
            if ban_number < len(self.backoff_schedule):
                duration = self.backoff_schedule[ban_number]
            else:
                # beyond schedule — permanent ban
                duration = -1

            # increment ban count for this IP
            self.ban_counts[ip] = ban_number + 1

            # add iptables rule
            self._add_iptables_rule(ip)

            # record the active ban
            self.active_bans[ip] = {
                'banned_at':  datetime.utcnow(),
                'duration':   duration,
                'ban_number': ban_number + 1
            }

            duration_str = (
                f"{duration} min" if duration != -1
                else "permanent"
            )
            print(
                f"[Blocker] Banned IP: {ip} "
                f"duration={duration_str} "
                f"ban_number={ban_number + 1}"
            )

            return duration

    def unban(self, ip):
        """
        Remove the iptables DROP rule for the given IP.
        """
        with self.lock:
            self._remove_iptables_rule(ip)
            self.active_bans.pop(ip, None)
            print(f"[Blocker] Unbanned IP: {ip}")

    def _add_iptables_rule(self, ip):
        """
        Run iptables command to DROP all traffic from IP.
        """
        try:
            subprocess.run(
                ['iptables', '-I', 'INPUT', '1',
                 '-s', ip, '-j', 'DROP'],
                check=True,
                capture_output=True
            )
            print(f"[Blocker] iptables DROP rule added for {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[Blocker] iptables error for {ip}: {e}")

    def _remove_iptables_rule(self, ip):
        """
        Run iptables command to remove DROP rule for IP.
        """
        try:
            subprocess.run(
                ['iptables', '-D', 'INPUT',
                 '-s', ip, '-j', 'DROP'],
                check=True,
                capture_output=True
            )
            print(
                f"[Blocker] iptables DROP rule removed for {ip}"
            )
        except subprocess.CalledProcessError as e:
            print(
                f"[Blocker] iptables remove error for {ip}: {e}"
            )

    def get_active_bans(self):
        """Return list of currently banned IPs and details."""
        with self.lock:
            return dict(self.active_bans)

    def get_ban_count(self, ip):
        """Return how many times an IP has been banned."""
        with self.lock:
            return self.ban_counts.get(ip, 0)
