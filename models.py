from app import db
from datetime import datetime
from sqlalchemy import Text, JSON

class Analysis(db.Model):
    """Model to store analysis results and metadata"""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # File metadata
    threat_model_filename = db.Column(db.String(255))
    block_diagram_filename = db.Column(db.String(255))
    crossmap_filename = db.Column(db.String(255))
    embed_properties_filename = db.Column(db.String(255))
    
    # Analysis results stored as JSON
    threats = db.Column(JSON)
    assets = db.Column(JSON)
    risks = db.Column(JSON)
    mitigations = db.Column(JSON)
    mitre_mappings = db.Column(JSON)
    recommendations = db.Column(JSON)
    embed_assessment = db.Column(JSON)
    embed_properties = db.Column(JSON)
    
    # Status and processing info
    status = db.Column(db.String(50), default='pending')
    error_message = db.Column(Text)
    
    def __repr__(self):
        return f'<Analysis {self.id}: {self.session_id}>'

class AuditLog(db.Model):
    """Model for security audit logging"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    session_id = db.Column(db.String(64))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    
    def __repr__(self):
        return f'<AuditLog {self.id}: {self.action}>'
