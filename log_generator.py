import time
import requests
import random
import datetime
import os

API_URL = "http://localhost:5000/api/logs"

def generate_log():
    modules = ['Web Server', 'Firewall', 'System']
    module = random.choice(modules)
    
    ip_list = ['192.168.1.10', '192.168.1.15', '10.0.0.5', '172.16.0.2', '8.8.8.8', '114.114.114.114']
    source_ip = random.choice(ip_list)
    
    if module == 'Web Server':
        events = [('HTTP_REQUEST', 'INFO', 'GET /index.html HTTP/1.1 200 OK'), 
                  ('HTTP_REQUEST', 'INFO', 'POST /login HTTP/1.1 200 OK'),
                  ('SQL_INJECTION_ATTEMPT', 'CRITICAL', 'GET /search?q=1 OR 1=1 HTTP/1.1 403 Forbidden')]
        event = random.choice(events)
        destination_ip = '192.168.1.100'
    elif module == 'Firewall':
        events = [('PORT_SCAN', 'WARNING', f'Multiple connection attempts from {source_ip}'),
                  ('CONNECTION_ALLOWED', 'INFO', f'Connection from {source_ip} to port 443 allowed')]
        event = random.choice(events)
        destination_ip = '192.168.1.254'
    else: # System
        events = [('AUTH_FAILURE', 'WARNING', f'Failed login attempt for user root from {source_ip}'),
                  ('AUTH_SUCCESS', 'INFO', f'Successful login for user admin from {source_ip}')]
        event = random.choice(events)
        destination_ip = '127.0.0.1'

    locations = ['United States', 'China', 'Russia', 'Brazil', 'Germany', 'India', 'Japan', 'South Korea', 'United Kingdom']
    location = random.choice(locations) if source_ip not in ['192.168.1.10', '192.168.1.15', '10.0.0.5', '172.16.0.2'] else 'Local Network'

    log_data = {
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'source_ip': source_ip,
        'destination_ip': destination_ip,
        'event_type': event[0],
        'severity': event[1],
        'raw_message': event[2],
        'source_module': module,
        'location': location
    }
    return log_data

from app import app
from database import db
from models import Log

def run_generator():
    print("Starting simulated log generator...")
    with app.app_context():
        while True:
            try:
                log_data = generate_log()
                new_log = Log(
                    timestamp=log_data['timestamp'],
                    source_ip=log_data['source_ip'],
                    destination_ip=log_data['destination_ip'],
                    event_type=log_data['event_type'],
                    severity=log_data['severity'],
                    raw_message=log_data['raw_message'],
                    source_module=log_data['source_module'],
                    location=log_data['location']
                )
                db.session.add(new_log)
                db.session.commit()
                print(f"Inserted log: {log_data['event_type']} from {log_data['source_ip']}")
            except Exception as e:
                print(f"Error inserting log: {e}")
                db.session.rollback()
            time.sleep(random.uniform(1.0, 5.0))

if __name__ == '__main__':
    run_generator()
