from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_migrate import Migrate
from datetime import datetime


db = SQLAlchemy()
migrate = Migrate()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='employee')
    image = db.Column(db.String(255), nullable=True)
    
    
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    
    
    preferred_language = db.Column(db.String(10), default='en')
    timezone = db.Column(db.String(50), default='UTC')
    theme = db.Column(db.String(20), default='light')
    
    
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    
    transactions = db.relationship('Transaction', backref='user', lazy=True, cascade='all, delete-orphan')
    
    @property
    def image_url(self):
        if self.image:
            
            if self.image.startswith(('http://', 'https://', '/static/')):
                return self.image
            
            import os
            from flask import url_for
            
            
            if os.path.exists(f"static/uploads/{self.image}"):
                return f"/static/uploads/{self.image}"
            
            elif os.path.exists(f"static/profile_images/{self.image}"):
                return f"/static/profile_images/{self.image}"
            
            return url_for('static', filename='image/logo copie 2.png')
        return url_for('static', filename='image/logo copie 2.png')
        
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def get_id(self):
        return str(self.id)
        
    def __repr__(self):
        return f'<User {self.username}>'


class Transaction(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    
    sender_name = db.Column(db.String(80), nullable=False)
    receiver_name = db.Column(db.String(80), nullable=False)
    sender_email = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False) 
    fee = db.Column(db.Float, nullable=False, default=0.0) 
    total_amount = db.Column(db.Float, nullable=False) 
    recipient_amount = db.Column(db.Float, nullable=False) 
    sender_number = db.Column(db.String(20), nullable=False)
    sender_country = db.Column(db.String(50), nullable=False)
    receiver_country = db.Column(db.String(50), nullable=False)
    sending_method = db.Column(db.String(50), nullable=False)
    receiver_number = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False) 
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    
    
    
    def __init__(self, **kwargs):
        super(Transaction, self).__init__(**kwargs)
    
    def __repr__(self):
        return f'<Transaction {self.id}: {self.amount} from {self.sender_name} to {self.receiver_name}>'


class WithdrawalRequest(db.Model):
    __tablename__ = 'withdrawal_request'  
    
    id = db.Column(db.Integer, primary_key=True)
    sender_name = db.Column(db.String(80), nullable=False)
    receiver_name = db.Column(db.String(80), nullable=False)
    receiver_email = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    source_country = db.Column(db.String(50), nullable=False)
    destination_country = db.Column(db.String(50), nullable=False)
    sending_method = db.Column(db.String(50), nullable=False)
    sender_number = db.Column(db.String(20), nullable=False)
    receiver_number = db.Column(db.String(20), nullable=False)
    proof_filename = db.Column(db.String(255), nullable=False)      
    status = db.Column(db.String(20), nullable=False, default='pending') 
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), onupdate=db.func.now())
    
    def __repr__(self):
        return f'<WithdrawalRequest {self.id} - {self.sender_name} to {self.receiver_name} ({self.amount})>'
    

class Appointment(db.Model):
    __tablename__ = 'appointement'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    date = db.Column(db.String(50), nullable=False)  
    time = db.Column(db.String(50), nullable=False)  
    service = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    
    user = db.relationship('User', backref=db.backref('appointments', lazy=True))
    
    def __repr__(self):
        return f'<Appointment {self.name} - {self.date} {self.time}>' 

class PayPALTransaction(db.Model):
    __tablename__ = 'paypal_transaction'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_name = db.Column(db.String(80), nullable=False)
    receiver_name = db.Column(db.String(80), nullable=False)
    receiver_email = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    fee = db.Column(db.Float, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    receiver_number = db.Column(db.String(20), nullable=False)
    sender_batch_id = db.Column(db.String(120), nullable=True)
    sender_item_id = db.Column(db.String(120), nullable=True, index=True)
    payout_item_id = db.Column(db.String(120), nullable=True, index=True)
    transaction_id = db.Column(db.String(120), nullable=True)   

    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    status = db.Column(db.String(20), nullable=False, default='pending')
    updated_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), onupdate=db.func.now())

    def __repr__(self):
        return f'<PaypalTransaction {self.id} - {self.sender_name} to {self.receiver_name} ({self.amount})>'

class invastiseur(db.Model):
    __tablename__ = 'invastiseur'
    id=db.Column(db.Integer,primary_key=True)
    invastiseur_name=db.Column(db.String(80),nullable=False)
    invastiseur_email=db.Column(db.String(120),nullable=False)
    invasteur_phone=db.Column(db.String(20),nullable=False)
    invasteur_address=db.Column(db.String(200),nullable=False)
    invasteur_type=db.Column(db.String(20),nullable=False)
    invasteur_amount=db.Column(db.Float,nullable=False)
    invasteur_status=db.Column(db.String(20),nullable=False)
    invasteur_benefits_percentage=db.Column(db.Float,nullable=False)
    platform_benefits=db.Column(db.Float,nullable=False)
    invasteur_date=db.Column(db.DateTime,nullable=False,server_default=db.func.now())
    
    def __repr__(self):
        return f'<invastiseur {self.invastiseur_name} - {self.invastiseur_email}>'



    
class Debt(db.Model):
    __tablename__ = 'dept' 
    id = db.Column(db.Integer, primary_key=True)
    Borrower_name = db.Column(db.String(80), nullable=False)
    dept_date = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    expected_return_date = db.Column(db.DateTime, nullable=False)
    dept_amount = db.Column(db.Float, nullable=False)
    dept_type = db.Column(db.String(20), nullable=False)
    dept_status = db.Column(db.String(20), nullable=False)
    dept_description = db.Column(db.String(200), nullable=False)

    def __init__(self, **kwargs):
        super(Debt, self).__init__(**kwargs)

    def __repr__(self):
        return f'<Debt {self.Borrower_name} - {self.dept_date} - {self.dept_type} - {self.expected_return_date} - {self.dept_amount}>'
