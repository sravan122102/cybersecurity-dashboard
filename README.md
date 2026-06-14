# Cybersecurity Operations Center (SOC) Simulator

![Dashboard Preview](https://img.shields.io/badge/UI-Glassmorphism-blue?style=flat-square)
![Tech Stack](https://img.shields.io/badge/Backend-Python_Flask-green?style=flat-square)
![Frontend](https://img.shields.io/badge/Frontend-Vanilla_JS_&_CSS-yellow?style=flat-square)

A professional-grade, real-time **Cybersecurity Dashboard** designed to simulate a Security Operations Center (SOC) environment. This full-stack application ingests mock web traffic logs, analyzes them through a custom detection engine, and displays actionable alerts and analytics on a stunning real-time interface.

## 🌟 Key Features

* **Real-time Threat Detection**: Continuously monitors incoming logs against predefined security rules (`rules.yaml`) to detect Brute Force attacks, SQL Injections, and Port Scans.
* **Geographic Data Simulation**: Automatically assigns realistic global locations to incoming IP addresses to simulate international web traffic.
* **Actionable Mitigations**: Threat engine intelligently assigns specific, actionable mitigation strategies based on the detected threat vectors.
* **Live System Health**: Streams live host hardware metrics (CPU and RAM utilization) to the dashboard header.
* **Premium Glassmorphism UI**: A visually striking, dark-mode frontend featuring frosted-glass elements, neon accents, buttery-smooth micro-animations, and dynamic Chart.js visualizations.
* **WebSockets Integration**: Instantaneous alert notifications pushed directly to the client without needing a page refresh.

## 🛠️ Technology Stack

* **Backend**: Python 3.11, Flask, SQLite (Database), Flask-SocketIO (WebSockets)
* **Frontend**: HTML5, Vanilla CSS3 (Custom Glassmorphism Design), Vanilla JavaScript
* **Data Visualization**: Chart.js
* **System Metrics**: Psutil

## 🚀 Getting Started

### Prerequisites
Make sure you have Python installed on your system.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sravan122102/cybersecurity-dashboard.git
   cd cybersecurity-dashboard
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start the main web server:
   ```bash
   python app.py
   ```

4. Start the background daemons (open these in separate terminal windows):
   ```bash
   python log_generator.py
   python detection_engine.py
   ```

5. Access the dashboard:
   Open your browser and navigate to `http://localhost:5000`
   
   **Default Login Credentials:**
   * **Username:** `admin`
   * **Password:** `admin123`

## 📂 Project Structure

* `app.py`: The core Flask API server and WebSocket handler.
* `log_generator.py`: Daemon that constantly generates realistic, randomized mock web traffic logs.
* `detection_engine.py`: Daemon that analyzes logs and raises alerts based on detected threats.
* `models.py`: Database schema definitions (Logs, Threats, Users).
* `rules.yaml`: Customizable threat detection rules and thresholds.
* `static/`: Contains the frontend assets (HTML, CSS, JS).

---
*Built for advanced cybersecurity monitoring and simulation.*
