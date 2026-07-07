#!/usr/bin/env python3
"""
Project 07 – SIEM Correlation Engine (Debug Version)
"""

import os
import sys
import time
import json
import yaml
import re
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import socketio

# ---------- CONFIG ----------
RULES_FILE = "rules.yaml"
MITRE_FILE = "mitre_attack.json"
LOG_DIR = "logs"
ALERT_QUEUE = []
ALERT_LOCK = threading.Lock()
SIO_SERVER = "http://127.0.0.1:5002"

# ---------- SOCKETIO ----------
sio = socketio.Client()
try:
    sio.connect(SIO_SERVER)
    print("[*] Connected to dashboard.")
    # Send a test alert to verify connectivity
    test_alert = {
        "timestamp": datetime.now().isoformat(),
        "rule_id": "TEST",
        "rule_name": "🔔 Test Connection Alert",
        "description": "This confirms the SIEM engine can send alerts to the dashboard.",
        "severity": "INFO",
        "mitre_id": "T0000",
        "mitre_name": "Test",
        "mitre_tactic": "Test",
        "trigger_event": {"test": "data"},
        "key": "test"
    }
    try:
        sio.emit('siem_alert', test_alert)
        print("[*] Test alert sent successfully.")
    except Exception as e:
        print(f"[!] Failed to send test alert: {e}")
except Exception as e:
    print(f"[!] Dashboard connection failed: {e}")

# ---------- LOAD DATA ----------
with open(MITRE_FILE, 'r') as f:
    MITRE_DATA = json.load(f)

with open(RULES_FILE, 'r') as f:
    RULES = yaml.safe_load(f)['rules']

rule_state = defaultdict(lambda: deque(maxlen=1000))

# ---------- PARSE LOG LINES ----------
def parse_log_line(line):
    parts = line.strip().split()
    if len(parts) < 3:
        return None
    try:
        timestamp = datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    event_type = parts[2]
    event = {
        "timestamp": timestamp,
        "event_type": event_type,
    }
    for part in parts[3:]:
        if '=' in part:
            k, v = part.split('=', 1)
            event[k] = v
    return event

# ---------- EVALUATE RULES ----------
def evaluate_rules(event):
    for rule in RULES:
        cond = rule['condition']
        if 'event_type' in cond and cond['event_type'] != event.get('event_type'):
            continue
        if 'command_pattern' in cond:
            command = event.get('command', '')
            if not re.search(cond['command_pattern'], command, re.IGNORECASE):
                continue
        if 'count' in cond and 'time_window' in cond:
            key = cond.get('source_ip', 'global')
            if 'source_ip' in cond:
                key = event.get(cond['source_ip'].strip('$'), 'unknown')
            state_key = f"{rule['id']}_{key}"
            buffer = rule_state[state_key]
            buffer.append(event['timestamp'])
            cutoff = event['timestamp'] - timedelta(seconds=cond['time_window'])
            while buffer and buffer[0] < cutoff:
                buffer.popleft()
            if len(buffer) >= cond['count']:
                generate_alert(rule, event, key)
                buffer.clear()
        elif 'count' not in cond:
            generate_alert(rule, event)

# ---------- GENERATE ALERT ----------
def generate_alert(rule, trigger_event, key=None):
    mitre_id = rule.get('mitre_technique')
    mitre_info = MITRE_DATA.get(mitre_id, {})
    alert = {
        "timestamp": trigger_event['timestamp'].isoformat(),
        "rule_id": rule['id'],
        "rule_name": rule['name'],
        "description": rule['description'],
        "severity": rule.get('severity', 'MEDIUM'),
        "mitre_id": mitre_id,
        "mitre_name": mitre_info.get('name', 'Unknown'),
        "mitre_tactic": mitre_info.get('tactic', ''),
        "trigger_event": trigger_event,
        "key": key,
    }
    with ALERT_LOCK:
        ALERT_QUEUE.append(alert)
        if len(ALERT_QUEUE) > 100:
            ALERT_QUEUE.pop(0)
    # Send via SocketIO with debug
    try:
        sio.emit('siem_alert', alert)
        print(f"[DEBUG] Alert emitted: {rule['name']}")
    except Exception as e:
        print(f"[ERROR] Failed to emit alert: {e}")
    print(f"[!] ALERT: {rule['name']} (MITRE {mitre_id}) - {trigger_event}")

# ---------- TAIL LOG FILES ----------
def tail_logs():
    log_file = os.path.join(LOG_DIR, "sample.log")
    if not os.path.exists(log_file):
        print(f"[!] Log file {log_file} not found. Creating empty file.")
        os.makedirs(LOG_DIR, exist_ok=True)
        open(log_file, 'w').close()
    with open(log_file, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                event = parse_log_line(line)
                if event:
                    evaluate_rules(event)
            else:
                time.sleep(0.1)

# ---------- MAIN ----------
if __name__ == "__main__":
    print("[*] SIEM Engine starting...")
    threading.Thread(target=tail_logs, daemon=True).start()
    print("[*] Log monitor started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down SIEM engine.")