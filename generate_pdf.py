from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.cell(0, 10, 'Cybersecurity and Threat Detection System', border=False, align='C')
        self.ln(8)
        self.set_font('helvetica', 'I', 12)
        self.cell(0, 10, 'Implementation Summary Document', border=False, align='C')
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('helvetica', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 8, title, 0, 1, 'L', fill=True)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('helvetica', '', 11)
        self.multi_cell(0, 6, body)
        self.ln()

pdf = PDF()
pdf.add_page()
pdf.set_auto_page_break(auto=True, margin=15)

modules = [
    {
        "title": "Module 1: User Authentication",
        "body": "Requirement: Secure access and role-based controls.\n\n"
                "How We Built It:\n"
                "- Used Python (Flask) alongside a local SQLite database (managed by Flask-SQLAlchemy) to store user credentials.\n"
                "- Passwords are not stored in plain text; utilized the `bcrypt` library to securely hash all passwords.\n"
                "- Implemented JSON Web Tokens (JWT) using `PyJWT`. When a user logs in via the `/api/auth/login` endpoint, they receive a token that must be attached to all future API requests.\n"
                "- Implemented Role-Based Access Control (RBAC) with three tiers: Admin, Analyst, and Viewer. Certain endpoints (like User Management) are locked behind an `@admin_required` decorator."
    },
    {
        "title": "Module 2: Log Collection",
        "body": "Requirement: Centralized ingestion of data from various sources (web servers, firewalls, etc.).\n\n"
                "How We Built It:\n"
                "- Created a `/api/logs` REST API endpoint in the Flask application (`app.py`) to receive incoming log data.\n"
                "- All logs are normalized and stored in the `logs_normalised` table in the SQLite database, tracking the timestamp, source IP, event type, severity, and the raw message.\n"
                "- To simulate a live network, built a standalone background Python script (`log_generator.py`). This script runs continuously, randomly generating realistic mock logs for Web Servers (HTTP requests), Firewalls (Connections allowed/blocked), and System Auth (logins), and sends them to the API."
    },
    {
        "title": "Module 3: Threat Detection",
        "body": "Requirement: Signature-based and anomaly-based techniques to identify malicious activity.\n\n"
                "How We Built It:\n"
                "- Developed a dedicated background daemon called `detection_engine.py` that runs alongside the web server.\n"
                "- The engine uses a configuration file (`rules.yaml`) that defines specific threat signatures. For example, a 'Brute Force' rule triggers if there are 5 AUTH_FAILURE events from the same IP within 300 seconds.\n"
                "- Every 10 seconds, the detection engine queries the database for recent logs and evaluates them against these YAML rules. If a threshold is met, it registers a Threat in the database."
    },
    {
        "title": "Module 4: Alert and Notification",
        "body": "Requirement: Dispatch alerts based on threat severity.\n\n"
                "How We Built It:\n"
                "- When the Threat Detection Engine confirms a threat, it generates an internal Alert record.\n"
                "- Integrated WebSockets into the backend using `Flask-SocketIO`. The moment an alert is created, the backend emits a real-time `new_alert` event to any connected web browsers.\n"
                "- For high-priority (CRITICAL or HIGH) threats, the engine executes simulated logic (printing to the terminal) to represent dispatching emergency Emails and SMS messages to Administrators."
    },
    {
        "title": "Module 5: Reporting and Dashboard",
        "body": "Requirement: Centralized, real-time visual interface and automated reporting features.\n\n"
                "How We Built It:\n"
                "- Built a custom, responsive frontend using plain HTML, pure Vanilla CSS (no heavy frameworks), and Vanilla JavaScript.\n"
                "- Designed a modern, dark-themed UI (`style.css`) with glassmorphism touches and smooth CSS micro-animations.\n"
                "- Utilized the `Chart.js` library to render the interactive 'Threat Timeline (7 Days)' graph.\n"
                "- The frontend connects to the WebSocket server to receive live data. When a log is ingested or an alert is generated, the UI updates instantly-populating the 'Live Activity Feed' and popping up toast notifications without requiring a page refresh.\n"
                "- Built out the supplementary pages: a Threat history table, a searchable Log Explorer, and a Settings panel for Admins to view detection rules and manage user accounts."
    }
]

for m in modules:
    pdf.chapter_title(m["title"])
    pdf.chapter_body(m["body"])

pdf.output("Project_Implementation_Summary.pdf")
