from flask import Flask, request, jsonify, send_from_directory
import os
from flask_socketio import SocketIO
from database import db
from models import User, Log, Threat, Alert
import jwt
import datetime
from functools import wraps
import yaml
import psutil

app = Flask(__name__, static_folder='static', static_url_path='/')
app.config['SECRET_KEY'] = 'super-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersecurity.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Decorator to protect routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            # Bearer <token>
            parts = request.headers['Authorization'].split()
            if len(parts) == 2:
                token = parts[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401

        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'Admin':
            return jsonify({'message': 'Admin privilege required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/auth/register', methods=['POST'])
@token_required
@admin_required
def register(current_user):
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password') or not data.get('role'):
        return jsonify({'message': 'Missing data'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists'}), 400
        
    new_user = User(username=data['username'], role=data['role'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'message': 'Missing credentials'}), 400
            
        user = User.query.filter_by(username=data['username']).first()
        
        if not user:
            return jsonify({'message': 'Invalid credentials'}), 401

        if user.locked_until and user.locked_until > datetime.datetime.utcnow():
            return jsonify({'message': 'Account is temporarily locked'}), 403
            
        if user.check_password(data['password']):
            # Reset failed attempts
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            token = jwt.encode({
                'user_id': user.id,
                'role': user.role,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            return jsonify({'token': token, 'role': user.role}), 200
        else:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            db.session.commit()
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        import traceback
        return jsonify({'message': f"SERVER CRASH: {str(e)} | {traceback.format_exc()}"}), 500

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'role': current_user.role
    }), 200

@app.route('/api/logs', methods=['POST'])
def ingest_log():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing log data'}), 400
        
    try:
        new_log = Log(
            timestamp=data.get('timestamp', datetime.datetime.utcnow().isoformat()),
            source_ip=data.get('source_ip', '0.0.0.0'),
            destination_ip=data.get('destination_ip'),
            event_type=data.get('event_type', 'UNKNOWN'),
            severity=data.get('severity', 'INFO'),
            raw_message=data.get('raw_message', ''),
            source_module=data.get('source_module', 'Unknown'),
            location=data.get('location', 'Unknown')
        )
        db.session.add(new_log)
        db.session.commit()
        return jsonify({'message': 'Log ingested successfully'}), 201
    except Exception as e:
        return jsonify({'message': 'Error ingesting log', 'error': str(e)}), 500

@app.route('/api/simulate-attack', methods=['POST'])
@token_required
def simulate_attack(current_user):
    import random
    companies = ['Alpha', 'Beta', 'Gamma']
    attacked_company = random.choice(companies)
    
    threat_types = ['Massive DDoS Attack', 'Ransomware Encryption', 'Zero-Day Exploit', 'Database Exfiltration']
    threat = random.choice(threat_types)
    
    socketio.emit('new_alert', {
        'company': attacked_company,
        'threat_type': threat
    })
    
    return jsonify({'message': 'Attack simulated', 'company': attacked_company}), 200

@app.route('/api/internal/alerts', methods=['POST'])
def create_alert():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing data'}), 400
        
    try:
        now = datetime.datetime.utcnow()
        time_window = datetime.timedelta(minutes=10)
        start_time = (now - time_window).isoformat()
        
        # Deduplication logic
        existing_alert = Alert.query.filter(
            Alert.threat_type == data['threat_type'],
            Alert.source_ip == data['source_ip'],
            Alert.timestamp >= start_time,
            Alert.status.in_(['NEW', 'ACKNOWLEDGED'])
        ).first()
        
        if existing_alert:
            existing_alert.occurrences += 1
            db.session.commit()
            return jsonify({'message': 'Alert deduplicated', 'id': existing_alert.id}), 200
            
        new_alert = Alert(
            threat_id=data['threat_id'],
            timestamp=now.isoformat(),
            threat_type=data['threat_type'],
            source_ip=data['source_ip'],
            severity=data['severity'],
            description=data['description']
        )
        db.session.add(new_alert)
        db.session.commit()
        
        # Emit WebSocket event
        socketio.emit('new_alert', {
            'id': new_alert.id,
            'threat_type': new_alert.threat_type,
            'severity': new_alert.severity,
            'source_ip': new_alert.source_ip,
            'timestamp': new_alert.timestamp,
            'description': new_alert.description
        })
        
        if new_alert.severity in ['HIGH', 'CRITICAL']:
            print(f"[EMAIL MOCK] Dispatching email to Admin/Analyst for {new_alert.threat_type}")
        if new_alert.severity == 'CRITICAL':
            print(f"[SMS MOCK] Dispatching SMS to Admin for CRITICAL threat: {new_alert.threat_type}")
            
        return jsonify({'message': 'Alert created successfully', 'id': new_alert.id}), 201
    except Exception as e:
        return jsonify({'message': 'Error creating alert', 'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
@token_required
def get_alerts(current_user):
    alerts = Alert.query.filter(Alert.status.in_(['NEW', 'ACKNOWLEDGED'])).order_by(desc(Alert.timestamp)).limit(20).all()
    return jsonify([{
        'id': a.id,
        'threat_type': a.threat_type,
        'severity': a.severity,
        'source_ip': a.source_ip,
        'timestamp': a.timestamp,
        'status': a.status
    } for a in alerts]), 200

from sqlalchemy import func, desc

@app.route('/api/stats/summary', methods=['GET'])
@token_required
def get_summary_stats(current_user):
    now = datetime.datetime.utcnow()
    last_24h = (now - datetime.timedelta(hours=24)).isoformat()
    
    total_logs = db.session.query(func.count(Log.id)).filter(Log.timestamp >= last_24h).scalar()
    total_threats = db.session.query(func.count(Threat.id)).filter(Threat.timestamp >= last_24h).scalar()
    active_alerts = db.session.query(func.count(Alert.id)).filter(Alert.status.in_(['NEW', 'ACKNOWLEDGED'])).scalar()
    
    status = "Secure"
    if active_alerts > 0:
        critical_alerts = db.session.query(func.count(Alert.id)).filter(Alert.status.in_(['NEW', 'ACKNOWLEDGED']), Alert.severity == 'CRITICAL').scalar()
        if critical_alerts > 0:
            status = "Critical"
        else:
            status = "Warning"
            
    return jsonify({
        'total_logs_24h': total_logs,
        'total_threats_24h': total_threats,
        'active_alerts': active_alerts,
        'system_status': status
    }), 200

@app.route('/api/stats/timeline', methods=['GET'])
@token_required
def get_timeline(current_user):
    now = datetime.datetime.utcnow()
    last_7d = (now - datetime.timedelta(days=7)).isoformat()
    threats = Threat.query.filter(Threat.timestamp >= last_7d).all()
    timeline = {}
    for t in threats:
        date_str = t.timestamp[:10]
        if date_str not in timeline:
            timeline[date_str] = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        if t.severity in timeline[date_str]:
            timeline[date_str][t.severity] += 1
    return jsonify(timeline), 200

@app.route('/api/stats/top_sources', methods=['GET'])
@token_required
def get_top_sources(current_user):
    results = db.session.query(
        Threat.source_ip, func.count(Threat.id).label('count')
    ).group_by(Threat.source_ip).order_by(desc('count')).limit(10).all()
    return jsonify([{'source_ip': r[0], 'count': r[1]} for r in results]), 200

@app.route('/api/stats/recent_activity', methods=['GET'])
@token_required
def get_recent_activity(current_user):
    logs = Log.query.order_by(desc(Log.timestamp)).limit(20).all()
    return jsonify([{
        'timestamp': l.timestamp,
        'source_ip': l.source_ip,
        'event_type': l.event_type,
        'severity': l.severity
    } for l in logs]), 200

@app.route('/api/threats', methods=['GET'])
@token_required
def get_threats(current_user):
    query = Threat.query
    if request.args.get('severity'):
        query = query.filter(Threat.severity == request.args.get('severity'))
    threats = query.order_by(desc(Threat.timestamp)).limit(100).all()
    return jsonify([{
        'id': t.id,
        'timestamp': t.timestamp,
        'threat_type': t.threat_type,
        'severity': t.severity,
        'source_ip': t.source_ip,
        'confidence': t.confidence,
        'description': t.description,
        'mitigation_step': t.mitigation_step
    } for t in threats]), 200

@app.route('/api/logs/search', methods=['GET'])
@token_required
def search_logs(current_user):
    query = Log.query
    if request.args.get('source_ip'):
        query = query.filter(Log.source_ip == request.args.get('source_ip'))
    if request.args.get('event_type'):
        query = query.filter(Log.event_type == request.args.get('event_type'))
    if request.args.get('severity'):
        query = query.filter(Log.severity == request.args.get('severity'))
        
    logs = query.order_by(desc(Log.timestamp)).limit(100).all()
    return jsonify([{
        'id': l.id,
        'timestamp': l.timestamp,
        'source_ip': l.source_ip,
        'destination_ip': l.destination_ip,
        'event_type': l.event_type,
        'severity': l.severity,
        'raw_message': l.raw_message,
        'source_module': l.source_module,
        'location': l.location
    } for l in logs]), 200

@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'role': u.role,
        'created_at': u.created_at.isoformat() if u.created_at else None,
        'failed_login_attempts': u.failed_login_attempts,
        'locked_until': u.locked_until.isoformat() if u.locked_until else None
    } for u in users]), 200

@app.route('/api/rules', methods=['GET'])
@token_required
def get_rules(current_user):
    try:
        with open('rules.yaml', 'r') as file:
            rules = yaml.safe_load(file)['rules']
        return jsonify(rules), 200
    except Exception as e:
        return jsonify({'message': 'Error loading rules', 'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
@token_required
def get_health(current_user):
    # interval=0.1 ensures it measures usage over a fraction of a second, 
    # instead of returning 0.0 because it lacks a previous baseline
    return jsonify({
        'cpu': psutil.cpu_percent(interval=0.1),
        'memory': psutil.virtual_memory().percent
    }), 200

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists("static/" + path):
        return send_from_directory('static', path)
    else:
        return send_from_directory('static', 'index.html')

# Setup database and create default admin
def setup_db():
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path, exist_ok=True)
        
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='Admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Default admin created: admin / admin123")

# ============================================================
# BACKGROUND THREADS (run inside the same process as the app)
# ============================================================
import threading
import random
import time as _time

def _bg_log_generator():
    """Generates fake network logs every 1-5 seconds."""
    import datetime as dt
    _time.sleep(5)  # Wait for app to fully start
    print("[BG] Log Generator started.")
    
    modules_config = {
        'Web Server': {
            'events': [
                ('HTTP_REQUEST', 'INFO', 'GET /index.html HTTP/1.1 200 OK'),
                ('HTTP_REQUEST', 'INFO', 'POST /login HTTP/1.1 200 OK'),
                ('SQL_INJECTION_ATTEMPT', 'CRITICAL', 'GET /search?q=1 OR 1=1 HTTP/1.1 403 Forbidden')
            ],
            'dest_ip': '192.168.1.100'
        },
        'Firewall': {
            'events_fn': lambda src: [
                ('PORT_SCAN', 'WARNING', f'Multiple connection attempts from {src}'),
                ('CONNECTION_ALLOWED', 'INFO', f'Connection from {src} to port 443 allowed')
            ],
            'dest_ip': '192.168.1.254'
        },
        'System': {
            'events_fn': lambda src: [
                ('AUTH_FAILURE', 'WARNING', f'Failed login attempt for user root from {src}'),
                ('AUTH_SUCCESS', 'INFO', f'Successful login for user admin from {src}')
            ],
            'dest_ip': '127.0.0.1'
        }
    }
    ip_list = ['192.168.1.10', '192.168.1.15', '10.0.0.5', '172.16.0.2', '8.8.8.8', '114.114.114.114']
    local_ips = {'192.168.1.10', '192.168.1.15', '10.0.0.5', '172.16.0.2'}
    locations = ['United States', 'China', 'Russia', 'Brazil', 'Germany', 'India', 'Japan', 'South Korea', 'United Kingdom']

    while True:
        try:
            with app.app_context():
                module = random.choice(list(modules_config.keys()))
                cfg = modules_config[module]
                source_ip = random.choice(ip_list)
                
                if 'events' in cfg:
                    event = random.choice(cfg['events'])
                else:
                    event = random.choice(cfg['events_fn'](source_ip))
                
                location = 'Local Network' if source_ip in local_ips else random.choice(locations)
                
                new_log = Log(
                    timestamp=dt.datetime.utcnow().isoformat(),
                    source_ip=source_ip,
                    destination_ip=cfg['dest_ip'],
                    event_type=event[0],
                    severity=event[1],
                    raw_message=event[2],
                    source_module=module,
                    location=location
                )
                db.session.add(new_log)
                db.session.commit()
                print(f"[BG-LOG] {event[0]} from {source_ip}")
        except Exception as e:
            print(f"[BG-LOG ERROR] {e}")
            try:
                db.session.rollback()
            except:
                pass
        _time.sleep(random.uniform(1.0, 5.0))


def _bg_detection_engine():
    """Scans logs for threat patterns every 10 seconds."""
    import datetime as dt
    _time.sleep(10)  # Wait for some logs to accumulate
    print("[BG] Detection Engine started.")
    
    try:
        with open('rules.yaml', 'r') as f:
            rules = yaml.safe_load(f)['rules']
    except Exception as e:
        print(f"[BG-DETECT] Failed to load rules: {e}")
        return

    while True:
        try:
            with app.app_context():
                now = dt.datetime.utcnow()
                for rule in rules:
                    time_window = dt.timedelta(seconds=rule['time_window_seconds'])
                    start_time = (now - time_window).isoformat()
                    
                    results = db.session.query(
                        Log.source_ip, func.count(Log.id).label('count')
                    ).filter(
                        Log.event_type == rule['event_type'],
                        Log.timestamp >= start_time
                    ).group_by(Log.source_ip).all()
                    
                    for source_ip, count in results:
                        if count >= rule['threshold']:
                            existing = Threat.query.filter(
                                Threat.threat_type == rule['name'],
                                Threat.source_ip == source_ip,
                                Threat.timestamp >= start_time
                            ).first()
                            
                            if not existing:
                                mitigation = "Investigate immediately."
                                if rule['name'] == 'Brute Force Attack':
                                    mitigation = f"Temporarily block IP {source_ip} at the firewall and require password reset."
                                elif rule['name'] == 'SQL Injection Attempt':
                                    mitigation = f"Block IP {source_ip} at WAF. Audit web application inputs."
                                elif rule['name'] == 'Port Scan':
                                    mitigation = f"Drop connections from {source_ip} at edge router."
                                
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
                                print(f"[BG-THREAT] DETECTED: {rule['name']} from {source_ip}")
                                
                                # Send WebSocket alert
                                try:
                                    new_alert = Alert(
                                        threat_id=new_threat.id,
                                        timestamp=now.isoformat(),
                                        threat_type=new_threat.threat_type,
                                        source_ip=new_threat.source_ip,
                                        severity=new_threat.severity,
                                        description=new_threat.description
                                    )
                                    db.session.add(new_alert)
                                    db.session.commit()
                                    
                                    socketio.emit('new_alert', {
                                        'threat_type': new_threat.threat_type,
                                        'severity': new_threat.severity,
                                        'source_ip': new_threat.source_ip,
                                        'timestamp': new_threat.timestamp,
                                        'description': new_threat.description
                                    })
                                except Exception as e:
                                    print(f"[BG-ALERT ERROR] {e}")
        except Exception as e:
            print(f"[BG-DETECT ERROR] {e}")
            try:
                db.session.rollback()
            except:
                pass
        _time.sleep(10)


# Start background threads when the app boots
_bg_started = False

def start_background_tasks():
    global _bg_started
    if _bg_started:
        return
    _bg_started = True
    
    setup_db()
    
    t1 = threading.Thread(target=_bg_log_generator, daemon=True)
    t1.start()
    
    t2 = threading.Thread(target=_bg_detection_engine, daemon=True)
    t2.start()
    
    print("[APP] Background tasks launched.")

# This runs when gunicorn imports the app module
start_background_tasks()

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
