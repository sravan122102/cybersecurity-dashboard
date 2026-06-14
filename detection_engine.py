import time
import yaml
import datetime
from app import app
from database import db
from models import Log, Threat
from sqlalchemy import func
import requests

def load_rules(filepath='rules.yaml'):
    with open(filepath, 'r') as file:
        return yaml.safe_load(file)['rules']

def run_detection():
    rules = load_rules()
    print("Starting Threat Detection Engine...")
    
    with app.app_context():
        while True:
            now = datetime.datetime.utcnow()
            
            for rule in rules:
                time_window = datetime.timedelta(seconds=rule['time_window_seconds'])
                start_time = (now - time_window).isoformat()
                
                # Query logs matching the rule's event type within the time window
                results = db.session.query(
                    Log.source_ip, func.count(Log.id).label('count')
                ).filter(
                    Log.event_type == rule['event_type'],
                    Log.timestamp >= start_time
                ).group_by(Log.source_ip).all()
                
                for result in results:
                    source_ip, count = result
                    if count >= rule['threshold']:
                        # Check if threat already detected recently to avoid spamming the threats table
                        recent_threat = Threat.query.filter(
                            Threat.threat_type == rule['name'],
                            Threat.source_ip == source_ip,
                            Threat.timestamp >= start_time
                        ).first()
                        
                        if not recent_threat:
                            mitigation = "Investigate immediately."
                            if rule['name'] == 'Brute Force Attack':
                                mitigation = f"Temporarily block IP {source_ip} at the firewall and require password reset for targeted accounts."
                            elif rule['name'] == 'SQL Injection Attempt':
                                mitigation = f"Block IP {source_ip} at WAF. Audit web application inputs for SQL vulnerabilities."
                            elif rule['name'] == 'Port Scan':
                                mitigation = f"Drop connections from {source_ip} at edge router. Verify no ports are exposed unnecessarily."

                            new_threat = Threat(
                                timestamp=now.isoformat(),
                                threat_type=rule['name'],
                                severity=rule['severity'],
                                source_ip=source_ip,
                                confidence=rule['confidence'],
                                description=f"{rule['description']} ({count} occurrences)",
                                mitigation_step=mitigation
                            )
                            db.session.add(new_threat)
                            db.session.commit()
                            print(f"THREAT DETECTED: {rule['name']} from {source_ip}")
                            
                            # Send to Alerting module
                            try:
                                import os
                                port = os.environ.get('PORT', 5000)
                                requests.post(f"http://127.0.0.1:{port}/api/internal/alerts", json={
                                    "threat_id": new_threat.id,
                                    "threat_type": new_threat.threat_type,
                                    "severity": new_threat.severity,
                                    "source_ip": new_threat.source_ip,
                                    "timestamp": new_threat.timestamp,
                                    "description": new_threat.description
                                })
                            except Exception as e:
                                print(f"Failed to trigger alert: {e}")
                            
            time.sleep(10) # Run detection cycle every 10 seconds

if __name__ == '__main__':
    run_detection()
