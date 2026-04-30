# HNG Anomaly Detection Engine

A production-grade, real-time DDoS and anomaly detection daemon built for HNG's cloud.ng — a globally accessible Nextcloud-powered cloud storage platform. The engine watches all incoming HTTP traffic, learns what normal looks like, and automatically blocks threats before they cause damage.

---

## Live Deployment

| | |
|---|---|
| **Server IP** | `54.146.254.224` |
| **Dashboard** | https://hng-dashboard.mooo.com |
| **Nextcloud** | http://54.146.254.224 (IP only) |
| **GitHub** | https://github.com/Mercytunz/hng-anomaly-detector |

---

## Why Python?

Python was chosen for this project for the following reasons:

- **`collections.deque`** — Python's built-in deque is the ideal data structure for implementing sliding windows with O(1) append and O(1) eviction from both ends
- **`threading`** — Python's threading module makes it straightforward to run the monitor, baseline tracker, detector, unbanner, and dashboard simultaneously as background threads
- **`subprocess`** — Direct access to `iptables` system commands without any wrappers or libraries
- **Readability** — Security and detection logic needs to be auditable. Python's clean syntax makes every decision in the code transparent
- **Zero bloat** — The entire daemon runs on just three pip packages: `pyyaml`, `requests`, and `psutil`

---

## How the Sliding Window Works

The sliding window is the core of the detection engine. It answers one question in real time: **"How many requests has this IP made in the last 60 seconds?"**

### Data Structure

Two separate deques are maintained:

```python
# One deque per IP address
ip_windows = defaultdict(deque)  # {ip: deque([t1, t2, t3...])}

# One global deque for all traffic
global_window = deque()          # deque([t1, t2, t3...])
```

Each entry in the deque is a **Unix timestamp** of when a request arrived.

### How It Works — Step by Step

**On every new request:**

1. Get current timestamp: `now = time.time()`
2. Calculate the cutoff: `cutoff = now - 60`
3. Evict old timestamps from the LEFT of the deque:
```python
while window and window[0] < cutoff:
    window.popleft()
```
4. Append new timestamp to the RIGHT:
```python
window.append(now)
```
5. Count the window: `rate = len(window)`

### Why Deque?

A deque (double-ended queue) allows O(1) operations on both ends:
- `append()` on the right — O(1)
- `popleft()` on the left — O(1)

This means eviction is instant regardless of how many requests are in the window. No sorting, no scanning, no resetting counters.


---

## How the Baseline Works

The baseline answers: **"What does normal traffic look like right now?"**

### Window Size

The baseline maintains a rolling deque of **per-second request counts**:

```python
per_second_counts = deque(maxlen=1800)  # 30 min × 60 sec
```

Every second, the count of requests that arrived in that second is recorded. The deque automatically drops the oldest entry when it reaches 1800 slots — always keeping exactly the last 30 minutes.

### Recalculation Interval

Every **60 seconds**, mean and standard deviation are recalculated from all data points in the rolling window:

```python
mean   = sum(data) / len(data)
stddev = sqrt(sum((x - mean)² for x in data) / len(data))
```

### Hourly Slots

Traffic patterns change throughout the day — 3am looks very different from 3pm. To handle this, the baseline maintains **separate deques per hour**:

```python
hourly_slots = {
    0:  deque(maxlen=3600),   # midnight traffic
    14: deque(maxlen=3600),   # 2pm traffic
    ...
}
```

When recalculating, the **current hour's data is preferred** if it has at least 30 samples. Otherwise it falls back to the full 30-minute rolling window.

### Floor Values

On startup, the server has no traffic history. Floor values prevent false positives and division by zero:

```yaml
floor_mean:   1.0   # minimum mean value
floor_stddev: 0.5   # minimum stddev value
```

These floors are only active until enough real traffic data is collected. Once the baseline has sufficient data, real values take over.

### Why This Matters

The baseline is **never hardcoded**. It continuously learns from real traffic. If your server normally handles 50 req/s, that becomes the baseline. If it normally handles 2 req/s, that becomes the baseline. The detection logic adapts to whatever your actual traffic looks like.

---

## Detection Logic

An anomaly is flagged when **either condition fires first**:

| Condition | Formula | Threshold |
|---|---|---|
| Z-score | `(rate - mean) / stddev` | > 3.0 |
| Rate multiplier | `rate / mean` | > 5x |

**Error surge:** If an IP's 4xx/5xx error rate is 3x the baseline error rate, its z-score threshold is automatically tightened from 3.0 to 1.5.

---

## How iptables Blocks an IP

When a per-IP anomaly is detected, the blocker runs:

```bash
iptables -I INPUT 1 -s <IP> -j DROP
```

This **inserts a DROP rule at position 1** (top) of the INPUT chain. The Linux kernel discards all packets from that IP before they reach Nginx, Nextcloud, or any application — the attacker gets no response at all.

### Ban Backoff Schedule

Repeat offenders get progressively longer bans:

| Offence | Duration |
|---|---|
| 1st | 10 minutes |
| 2nd | 30 minutes |
| 3rd | 2 hours |
| 4th+ | Permanent |

Auto-unban removes the iptables rule and notifies Slack when a ban expires.

---

## Setup Instructions (Fresh VPS)

### Prerequisites
- Ubuntu 22.04 LTS
- Minimum 2 vCPU, 2GB RAM
- Ports open: 22, 80, 443, 8080

### Step 1: Update the Server
```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Docker
```bash
sudo apt install -y ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

### Step 3: Clone the Repository
```bash
git clone https://github.com/Mercytunz/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### Step 4: Set Up Slack
1. Create a Slack workspace and a `#security-alerts` channel
2. Go to https://api.slack.com/apps and create a new app
3. Enable Incoming Webhooks and copy your webhook URL

### Step 5: Create docker-compose.yml
```bash
cat > docker-compose.yml << 'EOF'
services:
  nextcloud:
    image: kefaslungu/hng-nextcloud
    container_name: nextcloud
    restart: always
    volumes:
      - nextcloud_data:/var/www/html
      - HNG-nginx-logs:/var/log/nginx:ro
    networks:
      - cloudnet

  nginx:
    image: nginx:latest
    container_name: nginx
    restart: always
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - HNG-nginx-logs:/var/log/nginx
    depends_on:
      - nextcloud
    networks:
      - cloudnet

  detector:
    build: ./detector
    container_name: detector
    restart: always
    environment:
      - PYTHONUNBUFFERED=1
      - SLACK_WEBHOOK_URL=YOUR_SLACK_WEBHOOK_URL_HERE
    volumes:
      - ./detector:/app
      - HNG-nginx-logs:/var/log/nginx:ro
    network_mode: host
    cap_add:
      - NET_ADMIN
    depends_on:
      - nginx

volumes:
  nextcloud_data:
  HNG-nginx-logs:
    name: HNG-nginx-logs

networks:
  cloudnet:
    driver: bridge
EOF
```

### Step 6: Pull Nextcloud Image
```bash
docker pull kefaslungu/hng-nextcloud
```

### Step 7: Start Everything
```bash
docker compose up -d --build
```

### Step 8: Verify Installation
```bash
# All three containers should show "Up"
docker ps

# Detector should show startup messages
docker logs -f detector

# Dashboard should return HTML
curl http://localhost:8080

# iptables should be accessible
docker exec detector iptables -L -n
```

### Step 9: Set Up Domain
- Buy a domain or create a free subdomain at https://afraid.org
- Add an A record pointing to your server IP
- Visit your domain to confirm the dashboard loads

---

## Repository Structure



---

## Blog Post

[Read the beginner-friendly blog post here](https://mercytunz.hashnode.dev/how-i-built-a-real-time-ddos-detection-engine-from-scratch)


