from app import db
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.types import LargeBinary, Text

class User(UserMixin, db.Model):
    """User model for authentication and storing user information."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # User's master encryption key
    master_key = db.Column(LargeBinary, nullable=True)
    
    # Relationship to encrypted data
    encrypted_data = db.relationship('EncryptedData', backref='owner', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class EncryptedData(db.Model):
    """Model for storing encrypted data and metadata."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Metadata
    original_filename = db.Column(db.String(255), nullable=True)
    input_type = db.Column(db.String(20), nullable=False)  # 'text', 'txt', 'pdf', 'voice'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Encrypted content and search index
    encrypted_content = db.Column(LargeBinary, nullable=False)
    search_index = db.Column(Text, nullable=False)  # JSON string for the search index
    
    # Initialization vector and other crypto parameters
    iv = db.Column(LargeBinary, nullable=False)
    search_key = db.Column(LargeBinary, nullable=False)
    
    def __repr__(self):
        return f'<EncryptedData {self.id} ({self.input_type})>'
