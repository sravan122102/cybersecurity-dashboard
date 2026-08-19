#!/bin/bash
# Start the main Flask web server (background tasks auto-start inside app.py)
PORT="${PORT:-5000}"
gunicorn --bind 0.0.0.0:$PORT --threads 50 -w 1 app:app
