FROM python:3.11-slim

WORKDIR /app

# Install iptables
RUN apt-get update && \
    apt-get install -y iptables && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt --quiet

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["python3", "-u", "main.py"]
