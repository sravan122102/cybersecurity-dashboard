#!/bin/bash
# Initialize the database and default admin user before starting
python -c "from app import setup_db; setup_db()"

# Start the background log generator daemon
python log_generator.py &

# Start the background threat detection engine daemon
python detection_engine.py &

# Start the main Flask web server with Gunicorn and Eventlet for WebSockets
gunicorn -k eventlet -w 1 app:app
