from models import db, User, Transaction, WithdrawalRequest, Appointment
from flask import Flask
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance/app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db.init_app(app)

with app.app_context():
    # Create all database tables
    db.create_all()
    print("Database tables created successfully in instance/app.db")
