from database import db
from datetime import datetime
import bcrypt

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Viewer') # Admin, Analyst, Viewer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Log(db.Model):
    __tablename__ = 'logs_normalised'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False) # ISO 8601 format
    source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False) # INFO, WARNING, ERROR, CRITICAL
    raw_message = db.Column(db.Text, nullable=False)
    source_module = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=True, default='Unknown')
    
    # Indexes for fast querying
    __table_args__ = (
        db.Index('idx_timestamp', 'timestamp'),
        db.Index('idx_source_ip', 'source_ip'),
    )

class Threat(db.Model):
    __tablename__ = 'threats_detected'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False)
    threat_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    mitigation_step = db.Column(db.Text, nullable=True, default='Investigate immediately.')

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats_detected.id'), nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)
    threat_type = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='NEW') # NEW, ACKNOWLEDGED, RESOLVED, FALSE POSITIVE
    occurrences = db.Column(db.Integer, default=1)
