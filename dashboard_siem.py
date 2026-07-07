#!/usr/bin/env python3
"""
SIEM Dashboard – displays real‑time alerts with MITRE mapping.
Runs on port 5002.
"""
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

alerts = []

@app.route('/')
def index():
    return render_template('siem_dashboard.html')

@socketio.on('connect')
def handle_connect():
    print('SIEM dashboard client connected')
    for alert in alerts[-10:]:
        emit('siem_alert', alert)

@socketio.on('siem_alert')
def handle_alert(data):
    alerts.append(data)
    if len(alerts) > 100:
        alerts.pop(0)
    emit('siem_alert', data, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5002, debug=True)
