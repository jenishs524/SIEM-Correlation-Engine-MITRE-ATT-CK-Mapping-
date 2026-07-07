📁 SIEM Correlation Engine (MITRE ATT&CK Mapping)

Description
Ingests log events from files (syslog, application logs), applies correlation rules (time‑window, count, pattern), and maps alerts to MITRE ATT&CK techniques. Displays alerts on a live dashboard.

Navigate to the project folder.

Create a virtual environment (recommended):
bash

python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

    Install dependencies – each project has its own requirements.txt or lists the required packages.

    Run the main script as described in the project’s section.

    Note: Some projects require system tools (e.g., nmap, subfinder, httpx, zeek). Installation instructions are provided per project.

    

Core Technologies

    Python, Flask‑SocketIO, pyyaml

Features

    YAML‑based correlation rules (easily extendable)

    Event parsing with key=value fields

    Time‑based sliding windows

    MITRE ATT&CK mapping (local JSON file)

    Live dashboard with severity and MITRE IDs

Installation & Setup
bash

pip install flask flask-socketio eventlet pyyaml jinja2

Usage

    Run dashboard (Terminal 1):
    bash

python dashboard_siem.py

(listens on port 5002)

Run engine (Terminal 2):
bash

python siem_engine.py

    (tails logs/sample.log)

Testing
Write events to logs/sample.log (see sample format in code) to trigger rules.

Output

    Dashboard at http://127.0.0.1:5002 shows alerts.
