#!/bin/bash
# Initialize the database and default admin user before starting
python -c "from app import setup_db; setup_db()"

# Start the main Flask web server with native threads to avoid Eventlet/SQLite locks
gunicorn --threads 50 -w 1 app:app
