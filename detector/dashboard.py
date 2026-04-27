import time
import threading
import psutil
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler


class DashboardHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the live dashboard.
    Serves a single HTML page that auto-refreshes
    every 3 seconds.
    """

    # shared state — set by Dashboard class
    state = {}

    def do_GET(self):
        if self.path == '/':
            self.serve_dashboard()
        elif self.path == '/health':
            self.serve_health()
        else:
            self.send_error(404)

    def serve_health(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def serve_dashboard(self):
        html = self._build_html()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def _build_html(self):
        s = self.state

        # get current data
        banned_ips   = s.get('banned_ips', {})
        global_rate  = s.get('global_rate', 0)
        top_ips      = s.get('top_ips', [])
        mean         = s.get('mean', 0)
        stddev       = s.get('stddev', 0)
        uptime       = s.get('uptime', '0s')
        cpu          = psutil.cpu_percent()
        memory       = psutil.virtual_memory().percent
        refresh      = s.get('refresh_seconds', 3)
        now          = datetime.utcnow().strftime(
                           '%Y-%m-%d %H:%M:%S UTC'
                       )

        # build banned IPs table rows
        banned_rows = ''
        for ip, info in banned_ips.items():
            duration = info['duration']
            duration_str = (
                f"{duration} min"
                if duration != -1
                else "PERMANENT"
            )
            banned_at = info['banned_at'].strftime(
                '%H:%M:%S'
            )
            banned_rows += (
                f"<tr>"
                f"<td>{ip}</td>"
                f"<td>{duration_str}</td>"
                f"<td>{banned_at}</td>"
                f"<td>#{info['ban_number']}</td>"
                f"</tr>"
            )

        if not banned_rows:
            banned_rows = (
                "<tr><td colspan='4' style='text-align:center;"
                "color:#888'>No active bans</td></tr>"
            )

        # build top IPs table rows
        top_ip_rows = ''
        for ip, count in top_ips:
            top_ip_rows += (
                f"<tr><td>{ip}</td>"
                f"<td>{count} req/60s</td></tr>"
            )

        if not top_ip_rows:
            top_ip_rows = (
                "<tr><td colspan='2' style='text-align:center;"
                "color:#888'>No data yet</td></tr>"
            )

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector Dashboard</title>
    <meta http-equiv="refresh" content="{refresh}">
    <style>
        body {{
            font-family: monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
            margin: 0;
        }}
        h1 {{ color: #58a6ff; }}
        h2 {{ color: #8b949e; font-size: 14px;
              text-transform: uppercase; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }}
        .card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #58a6ff;
        }}
        .card .label {{
            font-size: 12px;
            color: #8b949e;
            margin-top: 4px;
        }}
        .danger {{ color: #f85149 !important; }}
        .warning {{ color: #e3b341 !important; }}
        .ok {{ color: #3fb950 !important; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #21262d;
            padding: 10px;
            text-align: left;
            font-size: 12px;
            color: #8b949e;
            text-transform: uppercase;
        }}
        td {{
            padding: 10px;
            border-top: 1px solid #30363d;
            font-size: 13px;
        }}
        .section {{ margin-bottom: 24px; }}
        .timestamp {{
            color: #8b949e;
            font-size: 12px;
            margin-bottom: 16px;
        }}
    </style>
</head>
<body>
    <h1>[SHIELD] HNG Anomaly Detector</h1>
    <div class="timestamp">
        Last updated: {now} |
        Auto-refresh: {refresh}s |
        Uptime: {uptime}
    </div>

    <div class="grid">
        <div class="card">
            <div class="value
                {'danger' if global_rate > mean * 3
                 else 'ok'}">{global_rate}</div>
            <div class="label">Global Req/s (last 60s)</div>
        </div>
        <div class="card">
            <div class="value
                {'danger' if len(banned_ips) > 0
                 else 'ok'}">{len(banned_ips)}</div>
            <div class="label">Banned IPs</div>
        </div>
        <div class="card">
            <div class="value
                {'warning' if cpu > 70
                 else 'ok'}">{cpu}%</div>
            <div class="label">CPU Usage</div>
        </div>
        <div class="card">
            <div class="value
                {'warning' if memory > 70
                 else 'ok'}">{memory}%</div>
            <div class="label">Memory Usage</div>
        </div>
        <div class="card">
            <div class="value">{mean:.2f}</div>
            <div class="label">Baseline Mean (req/s)</div>
        </div>
        <div class="card">
            <div class="value">{stddev:.2f}</div>
            <div class="label">Baseline Stddev</div>
        </div>
    </div>

    <div class="section">
        <h2>Banned IPs</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Duration</th>
                <th>Banned At</th>
                <th>Ban #</th>
            </tr>
            {banned_rows}
        </table>
    </div>

    <div class="section">
        <h2>Top 10 Source IPs</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Requests (last 60s)</th>
            </tr>
            {top_ip_rows}
        </table>
    </div>
</body>
</html>"""

    def log_message(self, format, *args):
        # silence default HTTP server logs
        pass


class Dashboard:
    """
    Runs the dashboard HTTP server in a
    background thread and updates its state
    every 3 seconds.
    """

    def __init__(self, config, blocker,
                 detector, baseline):
        self.port        = config['dashboard']['port']
        self.refresh     = config['dashboard']['refresh_seconds']
        self.blocker     = blocker
        self.detector    = detector
        self.baseline    = baseline
        self.start_time  = datetime.utcnow()

    def _get_uptime(self):
        delta = datetime.utcnow() - self.start_time
        seconds = int(delta.total_seconds())
        hours, remainder = divmod(seconds, 3600)
        minutes, secs    = divmod(remainder, 60)
        return f"{hours}h {minutes}m {secs}s"

    def _update_state(self):
        """Update shared state for the dashboard."""
        mean, stddev = self.baseline.get_stats()
        DashboardHandler.state = {
            'banned_ips':      self.blocker.get_active_bans(),
            'global_rate':     self.detector.get_global_rate(),
            'top_ips':         self.detector.get_top_ips(10),
            'mean':            mean,
            'stddev':          stddev,
            'uptime':          self._get_uptime(),
            'refresh_seconds': self.refresh,
        }

    def run(self):
        """
        Start HTTP server and update state loop.
        """
        # keep trying to bind port until successful
        server = None
        while server is None:
            try:
                server = HTTPServer(('0.0.0.0', self.port),
                                    DashboardHandler)
                print(
                    f"[Dashboard] Running on "
                    f"http://0.0.0.0:{self.port}"
                )
            except OSError:
                print(
                    f"[Dashboard] Port {self.port} busy, "
                    f"retrying in 3s..."
                )
                time.sleep(3)

        # start server in background thread
        server_thread = threading.Thread(
            target=server.serve_forever,
            daemon=True
        )
        server_thread.start()

        # update state every 3 seconds forever
        while True:
            try:
                self._update_state()
            except Exception as e:
                print(f"[Dashboard] State update error: {e}")
            time.sleep(self.refresh)
