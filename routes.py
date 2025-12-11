import os
import sys
import io
import json
import paypalrestsdk
from functools import wraps
from typing import Any
from datetime import datetime, timezone
from decimal import Decimal, ROUND_UP
import time
import uuid
from flask import Flask, flash, redirect, render_template, request, session, url_for, send_from_directory, jsonify
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, DateField, TimeField, validators, FloatField
from wtforms.validators import DataRequired, Email, Length, EqualTo, InputRequired
from sqlalchemy import func,extract
from werkzeug.utils import secure_filename
from flask_login import login_required, login_user, logout_user, current_user, LoginManager
from flask_mail import Mail, Message
from PIL import Image  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv



# Import db and User from models
try:
    from models import db, User, Transaction, WithdrawalRequest, Appointment, PayPALTransaction, invastiseur, Debt
except ImportError:
    try:
        from .models import db, User, Transaction, WithdrawalRequest, Appointment, PayPALTransaction
    except ImportError as e:
        print(f"Error importing models: {e}")
        raise

from flask_migrate import Migrate

# Import du service PayPal personnalisé



# Create Flask app
app = Flask(__name__)
# Set a strong secret key for session and CSRF protection
app.secret_key = os.environ.get('SECRET_KEY') or 'your-very-secret-key-here-12345'

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Create Tithe Form
class TitheForm(FlaskForm):
    Borrower_name = StringField("Borrower's Name", validators=[InputRequired()])
    tithe_date = DateField('Tithe Date', format='%Y-%m-%d', validators=[InputRequired()])
    expected_date_return = DateField('Expected Return Date', format='%Y-%m-%d', validators=[InputRequired()])
    tithe_amount = FloatField('Tithe Amount', validators=[InputRequired()])
    tithe_type = StringField('Tithe Type', validators=[InputRequired()])
    tithe_status = StringField('Tithe Status', validators=[InputRequired()])
    tithe_description = StringField('Description')

# Create Appointment Form
class AppointmentForm(FlaskForm):
    name = StringField('Name', [validators.DataRequired()])
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    date = DateField('Date', format='%Y-%m-%d', validators=[validators.DataRequired()])
    time = TimeField('Time', format='%H:%M', validators=[validators.DataRequired()])
    service = StringField('Service', [validators.DataRequired()])

class InvestorForm(FlaskForm):
    investor_name = StringField('Investor Name', validators=[InputRequired()])
    investor_email = StringField('Email', validators=[InputRequired(), Email()])
    investor_phone = StringField('Phone', validators=[InputRequired()])
    investor_address = StringField('Address', validators=[InputRequired()])
    type_of_investment = SelectField('Type of Investment', 
                                   choices=[
                                       ('web', 'Web Development'),
                                       ('mobile', 'Mobile App'),
                                       ('marketing', 'Digital Marketing'),
                                       ('other', 'Other')
                                   ], 
                                   validators=[InputRequired()])
    investor_amount = FloatField('Investment Amount', validators=[InputRequired()])
    investor_status = SelectField('Status',
                                choices=[
                                    ('available', 'Available'),
                                    ('pending', 'Pending'),
                                    ('completed', 'Completed'),
                                    ('cancelled', 'Cancelled')
                                ],
                                validators=[InputRequired()])
    investor_date = DateField('Investment Date', format='%Y-%m-%d', validators=[InputRequired()])

# Add CSRF token to all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with the app
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Create uploads directory if it doesn't exist
if not os.path.exists('uploads'):
    os.makedirs('uploads')


# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Initialize PayPal SDK
paypalrestsdk.configure({
    "mode": os.getenv("PAYPAL_MODE", "sandbox"),
    "client_id": os.getenv("PAYPAL_CLIENT_ID"),
    "client_secret": os.getenv("PAYPAL_CLIENT_SECRET")
})

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_DEBUG'] = True  # Enable debug output

# Verify email configuration
if not all([app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD']]):
    print("\n=== Email Configuration Error ===")
    print("Warning: Email credentials not properly configured. Email functionality will be disabled.")
    print("Please create a .env file in your project root with the following content:")
    print("MAIL_USERNAME=your-email@gmail.com")
    print("MAIL_PASSWORD=your-app-password  # Use App Password, not your Gmail password\n")
    print("To generate an App Password:")
    print("1. Go to your Google Account Settings")
    print("2. Navigate to Security > App Passwords")
    print("3. Generate a new app password for your application\n")

# Initialize Flask-Mail
mail = Mail(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # This is the name of the login view function

# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Configure upload folder - use absolute path
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']), exist_ok=True)

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Use PIL instead of imghdr for image MIME detection
def get_image_mime(data):
    try:
        img = Image.open(io.BytesIO(data))
        return img.format.lower()  # e.g. 'jpeg', 'png'
    except Exception:
        return None

# Decorator for role-based access
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_role = session.get('role', '').strip().lower()
            if current_role != role:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def home():
    return redirect('/login')
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect based on role
    if current_user.is_authenticated:
        print(f"User already authenticated. Role: {current_user.role}")
        return redirect_based_on_role(current_user)

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        remember = True if request.form.get('remember') else False
        print(f"Login attempt - Email: {email}")
        
        user = User.query.filter_by(email=email).first()
        print(f"User found: {user is not None}")
        if user:
            print(f"User role before check: {user.role}")

        if user and user.check_password(password):
            login_user(user, remember=remember)
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role.strip().lower() if user.role else ''
            session['user_image'] = f"uploads/{user.image}" if user.image else None
            
            print(f"Login successful - User: {user.username}, Role: {user.role}")
            flash('Login successful!', 'success')

            # Redirect based on role
            return redirect_based_on_role(user)
        else:
            print("Login failed - Invalid email or password")
            flash('Invalid email or password', 'error')

    return render_template('login.html')

def redirect_based_on_role(user):
    role = user.role.strip().lower() if user.role else ''
    next_page = request.args.get('next')
    
    print(f"Redirecting user - Username: {user.username}, Role: '{user.role}', Normalized: '{role}'")
    
    if role == 'admin':
        print("Redirecting to admin view")
        return render_template('adminview.html')
    else:
        print("Redirecting to dashboard")
        return redirect(next_page) if next_page else redirect(url_for('dashboard'))

@app.route('/sigin', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        confirm = request.form['confirm_password'].strip()

        if not all([username, email, password, confirm]):
            return 'Please fill all fields', 400

        if password != confirm:
            return 'Passwords do not match', 400

        if User.query.filter_by(email=email).first():
            return 'Email already registered', 400

        user = User(username=username, email=email, role='employee')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')

    return render_template('sigin.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user data from current_user instead of session
    user_data = {
        'username': current_user.username,
        'email': current_user.email,
        'role': current_user.role,
        'image': f"uploads/{current_user.image}" if current_user.image else None
    }
    
    # Get recent transactions for the user
    recent_transactions = Transaction.query.filter_by(sender_email=current_user.email)\
        .order_by(Transaction.created_at.desc())\
        .limit(5).all()
    
    return render_template('dashboard.html', 
                         user=user_data, 
                         recent_transactions=recent_transactions)

@app.route('/paypal_send', methods=['GET', 'POST'])
def paypal():
    if request.method == 'POST':
        try:
            # Get form data
            sender_name = request.form.get('sender_name')
            receiver_name = request.form.get('receiver_name')
            receiver_email = request.form.get('receiver_email')
            amount = float(request.form.get('amount', 0))
            fee = float(request.form.get('fee', 0))
            total_amount = float(request.form.get('total_amount', 0))
            receiver_number = request.form.get('receiver_number', '')

            # Validate required fields
            if not all([sender_name, receiver_name, receiver_email, amount > 0]):
                error_msg = 'Missing required fields'
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'error': error_msg}), 400
                flash(error_msg, 'error')
                return redirect(url_for('paypal'))

            # Generate unique IDs for tracking
            sender_batch_id = str(uuid.uuid4())[:32]
            sender_item_id = f'item_{int(time.time())}_{uuid.uuid4().hex[:6]}'

            # Store the transaction
            new_transaction = PayPALTransaction(
                sender_name=sender_name,
                receiver_name=receiver_name,
                receiver_email=receiver_email,
                amount=amount,
                fee=fee,
                total_amount=total_amount,
                receiver_number=receiver_number,
                sender_item_id=sender_item_id,
                payout_item_id=None,  # This will be set after successful payout creation
                sender_batch_id=sender_batch_id,
                status='pending'
            )
            db.session.add(new_transaction)
            db.session.commit()

            try:
                # Create PayPal payout
                payout = paypalrestsdk.Payout({
                    'sender_batch_header': {
                        'sender_batch_id': sender_batch_id,
                        'email_subject': 'You have received a payment',
                        'email_message': f'You have received a payment of ${total_amount:.2f} from {sender_name}.'
                    },
                    'items': [{
                        'recipient_type': 'EMAIL',
                        'amount': {
                            'value': f'{total_amount:.2f}',
                            'currency': 'USD'
                        },
                        'receiver': receiver_email,
                        'note': f'Payment from {sender_name}',
                        'sender_item_id': sender_item_id,
                        'notification_language': 'en-US'
                    }]
                })

                if payout.create():
                    # Update transaction with payout batch ID and item ID
                    new_transaction.payout_batch_id = payout.batch_header.payout_batch_id
                    # Get the payout item ID from the response
                    if hasattr(payout, 'batch_header') and hasattr(payout.batch_header, 'links') and payout.batch_header.links:
                        for link in payout.batch_header.links:
                            if hasattr(link, 'rel') and link.rel == 'item' and hasattr(link, 'href'):
                                # Extract the payout_item_id from the link
                                # The link looks like: https://api.sandbox.paypal.com/v1/payments/payouts-item/78XK6NP6AELDE
                                new_transaction.payout_item_id = link.href.split('/')[-1]
                                break
                    db.session.commit()
                    
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({
                            'success': True,
                            'message': 'Payment processing started!',
                            'transaction_id': new_transaction.id,
                            'batch_id': payout.batch_header.payout_batch_id
                        })
                    
                    flash('Payment sent successfully! The recipient will be notified shortly.', 'success')
                else:
                    error_msg = str(payout.error)
                    new_transaction.status = 'failed'
                    new_transaction.error_message = error_msg
                    db.session.commit()
                    
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({
                            'success': False,
                            'error': error_msg
                        }), 400
                    
                    flash(f'Error: {error_msg}', 'error')

            except Exception as e:
                error_msg = str(e)
                new_transaction.status = 'failed'
                new_transaction.error_message = error_msg
                db.session.commit()
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({
                        'success': False,
                        'error': error_msg
                    }), 500
                
                flash(f'An error occurred: {error_msg}', 'error')

        except Exception as e:
            error_msg = f'Error processing request: {str(e)}'
            print(error_msg)  # Log the error
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'error': error_msg
                }), 400
            flash(error_msg, 'error')

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'error': 'Unexpected error occurred'
            }), 500

        return redirect(url_for('paypal'))
    
    # GET request - show the form
    return render_template('paypal.html')
from flask import request, jsonify
from datetime import datetime
import paypalrestsdk
from sqlalchemy import desc
# Import PayPALTransaction with proper error handling
try:
    from models import PayPALTransaction, db
except ImportError as e:
    print(f"Error importing PayPALTransaction: {e}")
    raise

#
@app.route('/paypal-webhook', methods=['POST'])
@csrf.exempt
def paypal_webhook():
    try:
        print("\n=== New Webhook Request ===")
        headers = {k: v for k, v in request.headers.items()}
        print("Headers:", json.dumps(headers, indent=2))
        raw_body = request.get_data(as_text=True)
        print(f"Raw body (first 500 chars):\n{raw_body[:500]}")

        # Parse JSON
        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({'status': 'error', 'message': 'Empty or invalid JSON payload'}), 400

        event_type = data.get('event_type')
        resource = data.get('resource', {})
        resource_type = data.get('resource_type')
        print(f"Processing event: {event_type} (Resource type: {resource_type})")

        # Verify webhook signature (bypass in development)
        headers_required = [
            'Paypal-Transmission-Id',
            'Paypal-Transmission-Time',
            'Paypal-Transmission-Sig',
            'Paypal-Cert-Url',
            'Paypal-Auth-Algo'
        ]
        is_development = True
        if all(h in request.headers for h in headers_required):
            if is_development:
                print("Development mode: Bypassing signature verification")
            else:
                try:
                    verified = paypalrestsdk.WebhookEvent.verify(
                        transmission_id=request.headers['Paypal-Transmission-Id'],
                        timestamp=request.headers['Paypal-Transmission-Time'],
                        webhook_id="3WS98722FU3418939",
                        event_body=raw_body,
                        cert_url=request.headers['Paypal-Cert-Url'],
                        actual_sig=request.headers['Paypal-Transmission-Sig'],
                        auth_algo=request.headers['Paypal-Auth-Algo']
                    )
                    if not verified:
                        return jsonify({'status': 'error', 'message': 'Invalid webhook signature'}), 400
                except Exception as e:
                    print(f"Verification error: {str(e)}. Bypassing in dev mode.")

        # Status mapping
        status_map = {
            'PAYMENT.PAYOUTS-ITEM.SUCCEEDED': 'completed',
            'PAYMENT.PAYOUTS-ITEM.DENIED': 'denied',
            'PAYMENT.PAYOUTS-ITEM.FAILED': 'failed',
            'PAYMENT.PAYOUTS-ITEM.UNCLAIMED': 'unclaimed',
            'PAYMENT.PAYOUTS-ITEM.BLOCKED': 'blocked',
            'PAYMENT.PAYOUTS-ITEM.CANCELED': 'canceled',
            'PAYMENT.PAYOUTS-ITEM.REFUNDED': 'refunded',
            'PAYMENT.PAYOUTS-ITEM.RETURNED': 'returned',
            'PAYMENT.PAYOUTS-ITEM.HELD': 'on_hold',
            'PAYMENT.PAYOUTSBATCH.DENIED': 'batch_denied',
            'PAYMENT.PAYOUTSBATCH.SUCCESS': 'batch_completed',
            'PAYMENT.PAYOUTSBATCH.PROCESSING': 'batch_processing'
        }
        new_status = status_map.get(event_type, event_type.lower())

        # Handle batch events
        if event_type.startswith('PAYMENT.PAYOUTSBATCH'):
            batch_header = resource.get('batch_header', {})
            batch_id = batch_header.get('payout_batch_id')
            sender_batch_id = batch_header.get('sender_batch_header', {}).get('sender_batch_id')
            if batch_id and sender_batch_id:
                transactions = PayPALTransaction.query.filter_by(sender_batch_id=sender_batch_id).all()
                for txn in transactions:
                    txn.status = new_status
                    txn.updated_at = datetime.utcnow()
                db.session.commit()
                print(f"Updated {len(transactions)} transactions for batch {batch_id} to {new_status}")
            return jsonify({'status': 'success', 'event_type': event_type, 'batch_id': batch_id, 'updated_count': len(transactions)}), 200

        # Handle individual payout items
        payout_item = resource.get('payout_item', {})
        sender_item_id = payout_item.get('sender_item_id')
        payout_item_id = resource.get('payout_item_id')

        tx = None
        if sender_item_id:
            tx = PayPALTransaction.query.filter_by(sender_item_id=sender_item_id).first()
        elif payout_item_id:
            tx = PayPALTransaction.query.filter_by(payout_item_id=payout_item_id).first()

        if tx:
            tx.status = new_status
            tx.updated_at = datetime.utcnow()
            tx.transaction_id = resource.get('transaction_id', tx.transaction_id)
            if 'receiver' in payout_item:
                tx.receiver_email = payout_item['receiver']
            if 'amount' in payout_item:
                tx.amount = payout_item['amount'].get('value', tx.amount)
                # Skip currency as it's not in the PayPALTransaction model
            db.session.commit()
            print(f"Updated transaction {tx.id} (sender_item_id={sender_item_id}) to status {new_status}")
        else:
            print(f"No transaction found for sender_item_id={sender_item_id} payout_item_id={payout_item_id}")

        return jsonify({'status': 'success', 'event_type': event_type, 'message': 'Webhook processed'}), 200

    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error_type': type(e).__name__,
            'details': str(e)
        }), 500
        
   
        



@app.route('/clientHome')
@role_required('employee')
def homepage():
    return render_template('clientHome.html')

def calculate_transaction_fee(amount):
    """Calculate transaction fee based on amount ranges.
    
    Args:
        amount (float): The transaction amount
        
    Returns:
        float: The calculated fee
    """
    fee_ranges = [
        (1, 25, 4.99),
        (26, 55, 6.99),
        (56, 75, 8.99),
        (76, 100, 10.99),
        (101, 125, 13.99),
        (126, 200, 15.99),
        (201, 300, 18.99),
        (301, 400, 22.99),
        (401, 500, 26.99),
        (501, 600, 31.99),
        (601, 700, 41.99),
        (701, 800, 50.99),
        (801, 900, 65.99),
        (901, 1000, 70.99),
        (1001, 1500, 85.99),
        (1501, 2000, 85.99),
        (2001, 2500, 100.99),
        (2501, 3000, 110.99),
        (3001, 3500, 120.99)
    ]
    
    for min_amt, max_amt, fee in fee_ranges:
        if min_amt <= amount <= max_amt:
            return fee
    
    # Default fee for amounts above the highest range
    return amount * 0.05  # 5% of the amount as fee

@app.route('/send', methods=['GET', 'POST'])
@role_required('employee')
def send():
    fee_ranges = [
        (1, 25, 4.99),
        (26, 55, 6.99),
        (56, 75, 8.99),
        (76, 100, 10.99),
        (101, 125, 13.99),
        (126, 200, 15.99),
        (201, 300, 18.99),
        (301, 400, 22.99),
        (401, 500, 26.99),
        (501, 600, 31.99),
        (601, 700, 41.99),
        (701, 800, 50.99),
        (801, 900, 65.99),
        (901, 1000, 70.99),
        (1001, 1500, 85.99),
        (1501, 2000, 85.99),
        (2001, 2500, 100.99),
        (2501, 3000, 110.99),
        (3001, 3500, 120.99),
        (3501, 4000, 150.99),
        (4001, 4500, 170.99),
        (4501, 5000, 190.99),
        (5001, 5500, 210.99),
        (5501, 6000, 230.99),
        (6001, 6500, 260.99),
        (6501, 7000, 280.99)
    ]
    
    if request.method == 'POST':
        sender_name = request.form['sender_name']
        receiver_name = request.form['receiver_name']
        sender_email = request.form['sender_email']
        amount = request.form['amount']
        sender_number = request.form['sender_number']
        sender_country = request.form['sender_country']
        receiver_country = request.form['receiver_country']
        sending_method = request.form['sending_method']
        receiver_number = request.form['receiver_number']
        
        # Check if fee was provided by the user
        user_provided_fee = None
        if 'transaction_fee' in request.form and request.form['transaction_fee']:
            try:
                user_provided_fee = float(request.form['transaction_fee'])
                if user_provided_fee < 0:
                    return 'Transaction fee cannot be negative', 400
            except ValueError:
                return 'Invalid transaction fee', 400

        try:
            amount = float(amount)
            if amount <= 0:
                return 'Amount must be greater than zero', 400
        except ValueError:
            return 'Invalid amount', 400

        try:
            sender_number = int(sender_number)
        except ValueError:
            return 'Invalid sender number', 400

        try:
            receiver_number = int(receiver_number)
        except ValueError:
            return 'Invalid receiver number', 400

        # Use user-provided fee if available, otherwise calculate it
        if user_provided_fee is not None:
            fee = user_provided_fee
            total_amount = float(Decimal(str(amount)) + Decimal(str(fee)))
            fee_source = 'user_provided'
        else:
            fee = calculate_transaction_fee(amount)
            total_amount = float(Decimal(str(amount)) + Decimal(str(fee)))
            fee_source = 'auto_calculated'
        
        # Calculate recipient amount (amount - fee)
        recipient_amount = max(0, amount - fee)  # Ensure it's not negative

        # Create and commit the transaction with all fields
        transaction = Transaction(
            user_id=current_user.id,  # Add the current user's ID
            sender_name=sender_name,
            receiver_name=receiver_name,
            sender_email=sender_email,
            amount=amount,
            fee=fee,
            total_amount=total_amount,
            recipient_amount=recipient_amount,
            sender_number=sender_number,
            sender_country=sender_country,
            receiver_country=receiver_country,
            sending_method=sending_method,
            receiver_number=receiver_number
        )
        db.session.add(transaction)
        db.session.commit()

        try:
            if not mail:
                raise Exception("Mail server not initialized")
                
            msg = Message(
                'New Transaction Alert',
                recipients=['jbmuisha@gmail.com'],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            
            # Plain text version
            msg.body = f"""
            New Transaction Alert
            
            A new transaction has been submitted with the following details:
            
            Sender Information:
            Name: {sender_name}
            Email: {sender_email}
            Phone: {sender_number}
            Country: {sender_country}
            
            Recipient Information:
            Name: {receiver_name}
            Phone: {receiver_number}
            Country: {receiver_country}
            
            Transaction Details:
            Amount to Send: ${amount:,.2f}
            Transaction Fee: ${fee:,.2f} {'(User Specified)' if fee_source == 'user_provided' else '(Auto-Calculated)'}
            Recipient will receive: ${recipient_amount:,.2f}
            Total to be paid: ${total_amount:,.2f}
            
            Sending Method: {sending_method}
            """
            
            # HTML version
            msg.html = f"""
            <html>
                <body>
                    <h2>New Transaction Alert</h2>
                    <p>A new transaction has been submitted with the following details:</p>
                    
                    <h3>Sender Information</h3>
                    <p><strong>Name:</strong> {sender_name}</p>
                    <p><strong>Email:</strong> {sender_email}</p>
                    <p><strong>Phone:</strong> {sender_number}</p>
                    <p><strong>Country:</strong> {sender_country}</p>
                    
                    <h3>Recipient Information</h3>
                    <p><strong>Name:</strong> {receiver_name}</p>
                    <p><strong>Phone:</strong> {receiver_number}</p>
                    <p><strong>Country:</strong> {receiver_country}</p>
                    
                    <h3>Transaction Details</h3>
                    <p><strong>Amount to Send:</strong> ${amount:,.2f}</p>
                    <p><strong>Transaction Fee:</strong> ${fee:,.2f} <em>{'(User Specified)' if fee_source == 'user_provided' else '(Auto-Calculated)'}</em></p>
                    <p><strong>Recipient will receive:</strong> ${recipient_amount:,.2f}</p>
                    <p><strong>Total to be paid:</strong> ${total_amount:,.2f}</p>
                    <p><strong>Sending Method:</strong> {sending_method}</p>
                    
                    <p>Please review this transaction in the admin panel.</p>
                </body>
            </html>
            """
            
            # Print debug info
            print("Attempting to send email...")
            print(f"Mail server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
            print(f"Using TLS: {app.config['MAIL_USE_TLS']}")
            print(f"From: {app.config['MAIL_DEFAULT_SENDER']}")
            print(f"To: {msg.recipients}")
            
            mail.send(msg)
            print("Email sent successfully!")
            flash('Transaction sent successfully and notification email has been sent!', 'success')
            
        except Exception as e:
            error_msg = f'Failed to send email: {str(e)}'
            print(error_msg)  # Print to console
            app.logger.error(error_msg)
            flash('Transaction was saved but failed to send notification email. Please check server logs.', 'warning')
            
        return redirect(url_for('send'))
    
    # Handle GET request
    return render_template('send.html', fee_ranges=fee_ranges, user=current_user)


@app.route('/collect', methods=['GET', 'POST'])
@role_required('employee')
def collect():
    
    if request.method == 'POST':
        try:
            # Debug: Print form data
            app.logger.info(f"Form data: {request.form}")
            
            # Get form data
            sender_name = request.form.get('sender_name')
            receiver_name = request.form.get('receiver_name')
            receiver_email = request.form.get('receiver_email')
            
            # Debug: Check if amount is present and valid
            amount_str = request.form.get('amount')
            if not amount_str:
                flash('Amount is required', 'error')
                return redirect(request.url)
                
            try:
                amount = float(amount_str)
                if amount <= 0:
                    flash('Amount must be greater than 0', 'error')
                    return redirect(request.url)
            except ValueError:
                flash('Invalid amount', 'error')
                return redirect(request.url)
            
            source_country = request.form.get('source_country')
            destination_country = request.form.get('destination_country')
            sending_method = request.form.get('sending_method')
            receiver_number = request.form.get('receiver_number')
            sender_number = request.form.get('sender_number')
            
            # Validate required fields
            required_fields = {
                'sender_name': 'Sender name',
                'receiver_name': 'Receiver name',
                'receiver_email': 'Receiver email',
                'source_country': 'Source country',
                'destination_country': 'Destination country',
                'sending_method': 'Sending method',
                'receiver_number': 'Receiver phone number',
                'sender_number': 'Sender phone number'
            }
            for field, name in required_fields.items():
                if not request.form.get(field):
                    flash(f'{name} is required', 'error')
                    return redirect(request.url)
            
            # File upload handling
            if 'imageprove' not in request.files:
                flash('Proof of payment is required', 'error')
                return redirect(request.url)
            
            file = request.files['imageprove']
            if file.filename == '':
                flash('No selected file', 'error')
                return redirect(request.url)
            
            # Ensure UPLOAD_FOLDER exists and is within the static directory
            upload_folder = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
            os.makedirs(upload_folder, exist_ok=True)
            
            app.logger.info(f"Upload folder set to: {upload_folder}")
                
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(upload_folder, filename)
                
                try:
                    file.save(file_path)
                    app.logger.info(f"File saved to: {file_path}")
                    
                    # Verify the file was saved
                    if not os.path.exists(file_path):
                        app.logger.error(f"Failed to save file to {file_path}")
                        flash('Failed to save file', 'error')
                        return redirect(request.url)

                    # Check if there are any transactions for this receiver (including pending)
                    total_sent = db.session.query(
                        func.sum(Transaction.amount)
                    ).filter(
                        Transaction.receiver_number == receiver_number,
                        Transaction.status.in_(['completed', 'pending'])  # Include both completed and pending
                    ).scalar()

                    # If no completed transactions found, reject the withdrawal
                    if not total_sent:
                        flash('No completed transactions found for this phone number. Please ensure the money has been sent and confirmed before withdrawing.', 'error')
                        return redirect(request.url)

                    # Calculate total already withdrawn (both pending and approved)
                    total_withdrawn = db.session.query(
                        func.sum(WithdrawalRequest.amount)
                    ).filter(
                        WithdrawalRequest.receiver_number == receiver_number,
                        WithdrawalRequest.status.in_(['pending', 'approved'])
                    ).scalar() or 0

                    # Calculate available balance (total received - total withdrawn)
                    available_balance = total_sent - total_withdrawn

                    # Check if requested amount is available
                    if amount > available_balance:
                        flash(f'Insufficient balance. Available: ${available_balance:,.2f}', 'error')
                        return redirect(request.url)
                        
                    
                    # Create withdrawal request record
                    withdrawal_request = WithdrawalRequest(
                        sender_name=sender_name,
                        receiver_name=receiver_name,
                        receiver_email=receiver_email,
                        amount=amount,
                        source_country=source_country,
                        destination_country=destination_country,
                        sending_method=sending_method,
                        receiver_number=receiver_number,
                        sender_number=sender_number,
                        proof_filename=filename,
                        status='pending'
                    )
                    db.session.add(withdrawal_request)
                    db.session.commit()
                    
                    # Send email notification to admin
                    try:
                        msg = Message(
                            'New Withdrawal Request Submitted',
                            recipients=['jbmuisha@gmail.com'],
                            sender=app.config['MAIL_DEFAULT_SENDER']
                        )
                        msg.body = f"""
                        A new withdrawal request has been submitted.
                        
                        Details:
                        - Sender: {sender_name}
                        - Receiver: {receiver_name}
                        - Amount: ${amount:,.2f}
                        - Source: {source_country}
                        - Destination: {destination_country}
                        - Sending Method: {sending_method}
                        - Sender Phone Number: {sender_number}
                    
                        
                        Please review this request in the admin panel.
                        """
                        
                        mail.send(msg)
                        app.logger.info("Withdrawal request email sent successfully")
                    except Exception as e:
                        app.logger.error(f"Failed to send withdrawal request email: {str(e)}")
                        flash('Withdrawal request submitted successfully but failed to send notification email. Please check server logs.', 'warning')
                    app.logger.info("Withdrawal record created successfully")
                    
                    flash('Withdrawal request submitted successfully!', 'success')
                    return redirect(url_for('collect'))
                    
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f'Error saving file or database operation: {str(e)}')
                    # Remove the file if it was created but DB operation failed
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    flash('An error occurred while processing your request', 'error')
                    return redirect(url_for('collect'))
            else:
                flash('Invalid file type. Please upload an image or PDF.', 'error')
                return redirect(request.url)

        except Exception as e:
            app.logger.error(f'Unexpected error in collect route: {str(e)}', exc_info=True)
            flash('An unexpected error occurred. Please try again later.', 'error')
            return redirect(url_for('collect'))
    
    # For GET request, just render the form
    return render_template('collect.html',  user=current_user)

# Admin Views
@app.route('/adminview')
@role_required('admin')
def adminview():
    return render_template('adminView.html')

@app.route('/appointment', methods=['GET'])
@login_required
def appointment():
    """Display the appointment scheduling form"""
    # CSRF token is automatically included by Flask-WTF's CSRFProtect
    return render_template('appointement.html')


@app.route('/api/orders', methods=['POST'])
@login_required
def paypal_create_order():
    """Crée une commande PayPal"""
    try:
        data = request.get_json(silent=True) or {}
        amount = float(data.get('amount', 0))
        currency = (data.get('currency') or 'USD').upper()
        
        if amount <= 0:
            return jsonify({'error': 'Le montant doit être supérieur à 0'}), 400
        
        # Créer la commande via notre service
        order = paypal_service.create_order(amount, currency)
        
        # Retourner la réponse formatée
        return jsonify({
            'order_id': order['id'],
            'status': order['status'],
            'links': {link['rel']: link['href'] for link in order.get('links', [])}
        })
        
    except Exception as e:
        app.logger.error(f"Erreur création commande PayPal: {str(e)}")
        return jsonify({'error': 'Erreur lors de la création de la commande'}), 500   

@app.route('/appointments', methods=['POST'])
@login_required
def handle_appointment():
    """Handle appointment form submission"""
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name')
            email = request.form.get('email')
            date = request.form.get('date')
            time = request.form.get('time')
            service = request.form.get('service')
            
            # Basic validation
            if not all([name, email, date, time, service]):
                flash('Please fill in all required fields', 'error')
                return redirect(url_for('appointment'))
            
            # Create new appointment
            new_appointment = Appointment(
                name=name,
                email=email,
                date=date,
                time=time,
                service=service,
                status='pending',  # Default status
                user_id=current_user.id  # Associate with current user
            )
            
            db.session.add(new_appointment)
            db.session.commit()
            
            flash('Appointment scheduled successfully!', 'success')
            return redirect(url_for('appointment'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating appointment: {str(e)}', exc_info=True)
            flash('An error occurred while scheduling your appointment. Please try again.', 'error')
    
    return redirect(url_for('appointment'))

@app.route('/userManager', methods=['GET', 'POST'])
@role_required('admin')
def user_manager():
    if request.method == 'POST':
        # Handle user update
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)
        if user:
            # Update basic fields
            if 'username' in request.form:
                user.username = request.form['username']
            if 'email' in request.form:
                user.email = request.form['email']
            if 'role' in request.form:
                user.role = request.form['role']
            if 'is_active' in request.form:
                user.is_active = request.form['is_active'].lower() == 'true'
            
            # Handle profile picture update
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file.filename != '':
                    # Remove old image if exists
                    if user.image:
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user.image))
                        except OSError:
                            pass
                    # Save new image
                    if file and allowed_file(file.filename):
                        filename = secure_filename(f"user_{user.id}_{file.filename}")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        user.image = filename
            
            db.session.commit()
            flash('User updated successfully!', 'success')
        else:
            flash('User not found!', 'error')
        return redirect(url_for('user_manager'))
    
    
    users = User.query.all()
    user_data = []
    for user in users:
        user_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'is_active': user.is_active,
            'image': user.image,
            'image_url': url_for('uploaded_file', filename=user.image) if user.image else url_for('static', filename='default-avatar.png')
        })
    
    return render_template('usermanager.html', users=user_data)

@app.route('/add_user', methods=['POST'])
@role_required('admin')
def add_user():
    user_id = request.form.get('user_id')
    username = request.form['username']
    email = request.form['email']
    password = request.form.get('password')
    role = request.form['role']
    image_file = request.files.get('image')
    image_path = None

    if image_file:
        image_data = image_file.read()
        mime_type = get_image_mime(image_data)

        if mime_type in ALLOWED_EXTENSIONS:
            filename = secure_filename(image_file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(file_path, 'wb') as f:
                f.write(image_data)
            # Save relative path to static folder (e.g. "uploads/filename.jpg")
            image_path = os.path.join('uploads', filename)
        else:
            flash('Invalid image format. Allowed: jpg, png, gif.', 'error')
            return redirect(url_for('user_manager'))

    if user_id:
        user = User.query.get(user_id)
        user.username = username
        user.email = email
        user.role = role
        if password:
            user.set_password(password)
        if image_path:
            user.image = image_path
        flash('User updated successfully!', 'success')
    else:
        if not password:
            flash('Password is required for new users.', 'error')
        else:
            user = User(username=username, email=email, role=role, image=image_path)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('User added successfully!', 'success')

    return redirect(url_for('user_manager'))

@app.route('/edit_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    user.username = request.form['username']
    user.email = request.form['email']
    user.role = request.form['role']
    password = request.form.get('password')

    if password:
        user.set_password(password)

    image_file = request.files.get('image')
    if image_file:
        image_data = image_file.read()
        mime_type = get_image_mime(image_data)

        if mime_type in ALLOWED_EXTENSIONS:
            filename = secure_filename(image_file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(file_path, 'wb') as f:
                f.write(image_data)

            # Update user's image path
            user.image = os.path.join('uploads', filename)

    db.session.commit()
    flash('User updated successfully!', 'success')
    return redirect(url_for('user_manager'))

@app.route('/api/paypal/transactions/approve/<int:transaction_id>', methods=['POST'])
@login_required
@role_required('admin')
def approve_paypal_transaction(transaction_id):
    try:
        if not transaction_id:
            return jsonify({'error': 'Transaction ID is required'}), 400
            
        # Find the transaction by id (primary key)
        transaction = PayPALTransaction.query.get(transaction_id)
        
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
            
        if transaction.status != 'pending':
            return jsonify({
                'error': 'Only pending transactions can be approved',
                'current_status': transaction.status
            }), 400
            
        # Update transaction status to completed
        transaction.status = 'completed'
        transaction.updated_at = datetime.utcnow()
        db.session.commit()
        
        app.logger.info(f"Approved PayPal transaction: {transaction_id}")
        return jsonify({
            'success': True,
            'message': 'Transaction approved successfully',
            'transaction_id': transaction_id,
            'new_status': 'completed'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error approving PayPal transaction {transaction_id}: {str(e)}")
        return jsonify({
            'error': 'Failed to approve transaction',
            'details': str(e)
        }), 500

@app.route('/api/paypal/transactions/delete/<int:transaction_id>', methods=['DELETE'])
@login_required
@role_required('admin')
def delete_paypal_transaction(transaction_id):
    try:
        transaction = PayPALTransaction.query.get(transaction_id)
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
            
        db.session.delete(transaction)
        db.session.commit()
        
        app.logger.info(f"Deleted PayPal transaction: {transaction_id}")
        return jsonify({
            'success': True,
            'message': 'Transaction deleted successfully',
            'transaction_id': transaction_id
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting PayPal transaction {transaction_id}: {str(e)}")
        return jsonify({
            'error': 'Failed to delete transaction',
            'details': str(e)
        }), 500

@app.route('/investiseur', methods=['GET', 'POST'])
@role_required('admin')
def investiseur():
    form = InvestorForm()
    
    if form.validate_on_submit():
        try:
            is_edit = request.form.get('edit_mode') == 'true'
            investor_id = request.form.get('investor_id')
            
            # Get form data
            invastiseur_name = form.investor_name.data
            invastiseur_email = form.investor_email.data
            invasteur_phone = form.investor_phone.data
            invasteur_address = form.investor_address.data
            invasteur_type = form.type_of_investment.data
            invasteur_amount = form.investor_amount.data
            invasteur_status = form.investor_status.data
            invasteur_date = form.investor_date.data
            
            # Calculate benefits
            investor_share = 0.60
            platform_share = 0.40
            
            invastiseur_benefits = float(invasteur_amount) * investor_share
            platform_benefit = float(invasteur_amount) * platform_share
            
            if is_edit and investor_id:
                # Update existing investor
                investor = invastiseur.query.get_or_404(investor_id)
                investor.invastiseur_name = invastiseur_name
                investor.invastiseur_email = invastiseur_email
                investor.invasteur_phone = invasteur_phone
                investor.invasteur_address = invasteur_address
                investor.invasteur_type = invasteur_type
                investor.invasteur_amount = float(invasteur_amount)
                investor.invasteur_status = invasteur_status
                investor.invasteur_date = invasteur_date
                investor.invasteur_benefits_percentage = invastiseur_benefits
                investor.platform_benefits = platform_benefit
                
                db.session.commit()
                message = 'Investment updated successfully!'
            else:
                # Create new investor
                new_investor = invastiseur(
                    invastiseur_name=invastiseur_name,
                    invastiseur_email=invastiseur_email,
                    invasteur_phone=invasteur_phone,
                    invasteur_address=invasteur_address,
                    invasteur_type=invasteur_type,
                    invasteur_amount=float(invasteur_amount),
                    invasteur_status=invasteur_status,
                    invasteur_date=invasteur_date,
                    invasteur_benefits_percentage=invastiseur_benefits,
                    platform_benefits=platform_benefit
                )
                
                db.session.add(new_investor)
                db.session.commit()
                message = 'Investment added successfully!'
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'message': message,
                    'investor': {
                        'id': investor.id if is_edit else new_investor.id,
                        'name': invastiseur_name,
                        'email': invastiseur_email,
                        'phone': invasteur_phone,
                        'address': invasteur_address,
                        'type': invasteur_type,
                        'amount': float(invasteur_amount),
                        'status': invasteur_status,
                        'date': invasteur_date.strftime('%Y-%m-%d') if invasteur_date else None,
                        'benefits': round(invastiseur_benefits, 2),
                        'platform_benefits': round(platform_benefit, 2)
                    }
                })
                
            flash(message, 'success')
            return redirect(url_for('investiseur'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error processing investment: {str(e)}', exc_info=True)
            error_message = 'An error occurred while processing the investment.'
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'message': error_message
                }), 400
                
            flash(error_message, 'error')
    
    # GET request or form validation failed
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': False,
            'message': 'Invalid form data',
            'errors': form.errors
        }), 400
    
    investors = invastiseur.query.all()
    return render_template('investiseur.html', form=form, investors=investors)

@app.route('/edit/<int:id>', methods=['POST'])
@role_required('admin')
def edit_investiseur(id):
    investor = invastiseur.query.get_or_404(id)
    
    # Check if request is JSON or form data
    if request.is_json:
        data = request.get_json()
        form_data = {
            'investor_name': data.get('investor_name'),
            'investor_email': data.get('investor_email'),
            'investor_phone': data.get('investor_phone'),
            'investor_address': data.get('investor_address'),
            'type_of_investment': data.get('type_of_investment'),
            'investor_amount': data.get('investor_amount'),
            'investor_status': data.get('investor_status'),
            'investor_date': data.get('investor_date')
        }
    else:
        form_data = request.form
    
    try:
        # Update investor data
        investor.invastiseur_name = form_data.get('investor_name', investor.invastiseur_name)
        investor.invastiseur_email = form_data.get('investor_email', investor.invastiseur_email)
        investor.invasteur_phone = form_data.get('investor_phone', investor.invasteur_phone)
        investor.invasteur_address = form_data.get('investor_address', investor.invasteur_address)
        investor.invasteur_type = form_data.get('type_of_investment', investor.invasteur_type)
        
        # Handle amount and benefits calculation
        amount = form_data.get('investor_amount')
        if amount is not None:
            investor.invasteur_amount = float(amount)
            investor_share = 0.60
            platform_share = 0.40
            investor.invasteur_benefits_percentage = float(amount) * investor_share
            investor.platform_benefits = float(amount) * platform_share
        
        investor.invasteur_status = form_data.get('investor_status', investor.invasteur_status)
        
        # Handle date
        date_str = form_data.get('investor_date')
        if date_str:
            investor.invasteur_date = datetime.strptime(date_str, '%Y-%m-%d')
        
        db.session.commit()
        
        response_data = {
            'success': True,
            'message': 'Investment updated successfully!',
            'investor': {
                'id': investor.id,
                'name': investor.invastiseur_name,
                'email': investor.invastiseur_email,
                'phone': investor.invasteur_phone,
                'address': investor.invasteur_address,
                'type': investor.invasteur_type,
                'amount': investor.invasteur_amount,
                'status': investor.invasteur_status,
                'date': investor.invasteur_date.strftime('%Y-%m-%d') if investor.invasteur_date else None,
                'benefits': round(investor.invasteur_benefits_percentage, 2),
                'platform_benefits': round(investor.platform_benefits, 2)
            }
        }
        
        if request.is_json:
            return jsonify(response_data)
        else:
            flash(response_data['message'], 'success')
            return redirect(url_for('investiseur'))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating investment: {str(e)}', exc_info=True)
        error_message = 'An error occurred while updating the investment.'
        
        if request.is_json:
            return jsonify({
                'success': False,
                'message': error_message
            }), 400
        else:
            flash(error_message, 'error')
            return redirect(url_for('investiseur'))

@app.route('/delete/<int:id>', methods=['POST'])
@role_required('admin')
def delete_investiseur(id):
    try:
        investor = invastiseur.query.get_or_404(id)
        db.session.delete(investor)
        db.session.commit()
        flash('Investment deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting investment: {str(e)}', exc_info=True)
        flash('An error occurred while deleting the investment. Please try again.', 'error')
    return redirect(url_for('investiseur'))


@app.route('/appointments', methods=['GET', 'POST'])
@role_required('employee')
def appointments():
    form = AppointmentForm(request.form)
    
    if request.method == 'POST' and form.validate():
        try:
            # Create new appointment from form data
            new_appointment = Appointment(
                name=form.name.data,
                email=form.email.data,
                date=form.date.data.strftime('%Y-%m-%d'),
                time=form.time.data.strftime('%H:%M'),
                service=form.service.data,
                status='pending'
            )
            
            db.session.add(new_appointment)
            db.session.commit()
            
            flash('Appointment scheduled successfully!', 'success')
            return redirect(url_for('appointments'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating appointment: {str(e)}', exc_info=True)
            flash('An error occurred while scheduling your appointment. Please try again.', 'error')
    
    # For GET or invalid POST, show the form
    return render_template('appointement.html', form=form)

    

@app.route('/benefit', methods=['GET', 'POST'])
@role_required('admin')
def benefit():
    now = datetime.now()
    month = now.month
    year = now.year
    
    # Handle tithe payment status
    if request.method == 'POST' and 'mark_tithe_paid' in request.form:
        session['tithe_paid'] = True
        session['tithe_paid_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        flash('Tithe marked as paid successfully!', 'success')
        return redirect(url_for('benefit'))
    
    # Initialize variables with default values
    mobile_month = 0.0
    mobile_year = 0.0
    paypal_month = 0.0
    paypal_year = 0.0
    
    # Get mobile transactions for current month
    mobile_month_result = db.session.query(func.sum(Transaction.fee))\
        .filter(
            Transaction.status != "batch_denied",
            Transaction.sending_method == 'mobile',
            extract('month', Transaction.created_at) == month,
            extract('year', Transaction.created_at) == year
        ).scalar()
    
    if mobile_month_result is not None:
        mobile_month = float(mobile_month_result) if mobile_month_result else 0.0
    
    # Get mobile transactions for current year
    mobile_year_result = db.session.query(func.sum(Transaction.fee))\
        .filter(
            Transaction.status != "batch_denied",
            Transaction.sending_method == 'mobile',
            extract('year', Transaction.created_at) == year
        ).scalar()
    
    if mobile_year_result is not None:
        mobile_year = float(mobile_year_result) if mobile_year_result else 0.0
    
    # Get PayPal transactions for current month (not batch_denied or pending)
    paypal_month_result = db.session.query(func.sum(PayPALTransaction.fee))\
        .filter(
            ~PayPALTransaction.status.in_(["batch_denied", "pending"]),
            extract('month', PayPALTransaction.created_at) == month,
            extract('year', PayPALTransaction.created_at) == year
        ).scalar()
    
    if paypal_month_result is not None:
        paypal_month = float(paypal_month_result) if paypal_month_result else 0.0
    
    # Get PayPal transactions for current year (not batch_denied or pending)
    paypal_year_result = db.session.query(func.sum(PayPALTransaction.fee))\
        .filter(
            ~PayPALTransaction.status.in_(["batch_denied", "pending"]),
            extract('year', PayPALTransaction.created_at) == year
        ).scalar()
    
    if paypal_year_result is not None:
        paypal_year = float(paypal_year_result) if paypal_year_result else 0.0
    
    # Add flash message if no transactions found
    if not (mobile_month or mobile_year or paypal_month or paypal_year):
        flash("No transactions found")
    
    mobile_month_tal = mobile_month + paypal_month
    tithe_total = mobile_month_tal * 0.1
    
    # Check if tithe has been paid this month
    tithe_paid = session.get('tithe_paid', False)
    tithe_paid_date = session.get('tithe_paid_date')

    return render_template(
        'benefit.html',
        mobile_month=mobile_month,
        mobile_year=mobile_year,
        paypal_month=paypal_month,
        paypal_year=paypal_year,
        current_year=year,
        current_month=month,
        tithe_total=tithe_total,
        tithe_paid=tithe_paid,
        tithe_paid_date=tithe_paid_date
    )
@app.route('/appointment_view')
@role_required('admin')
def appointment_view():
    appointments = Appointment.query.all()
    return render_template('appointment_view.html', appointments=appointments)


@app.route('/accept/<int:appointment_id>', methods=['POST'])
@role_required('admin')
def accept_appointment(appointment_id):
    print(f"Accepting appointment {appointment_id}")
    appointment = Appointment.query.get_or_404(appointment_id)
    print(f"Current status: {appointment.status}")
    appointment.status = 'accepted'
    db.session.commit()
    print(f"New status: {appointment.status}")
    
    # Send email notification
    try:
        msg = Message("Appointment Accepted", 
                     sender="jbmuisha@gmail.com", 
                     recipients=[appointment.email])
        msg.body = f"""
        Hello {appointment.name},
        
        Your appointment for {appointment.service} on {appointment.date} at {appointment.time} has been accepted.
        
        Thank you for choosing our service!
        """
        mail.send(msg)
        flash('Appointment accepted and notification email sent!', 'success')
    except Exception as e:
        print(f"Error sending email: {e}")
        flash('Appointment accepted but failed to send email notification.', 'warning')
    
    return redirect(url_for('appointment_view'))
    msg.body = "Your appointment of " + appointment.service + "has been accepted. please would u come early to the office"
    mail.send(msg)
    return redirect(url_for('appointment_view'))
@app.route('/reject/<int:appointment_id>', methods=['POST'])
@role_required('admin')
def reject_appointment(appointment_id):
    print(f"Rejecting appointment {appointment_id}")
    appointment = Appointment.query.get_or_404(appointment_id)
    print(f"Current status: {appointment.status}")
    appointment.status = 'rejected'
    db.session.commit()
    print(f"New status: {appointment.status}")
    flash('Appointment rejected successfully!', 'success')
    msg = Message("Appointment Rejected", sender="jbmuisha@gmail.com", recipients=[appointment.email])
    msg.body = "Your appointment of " + appointment.service + "has been rejected. please would u come early to the office"
    mail.send(msg)
    return redirect(url_for('appointment_view'))


@app.route('/dept', methods=['GET', 'POST'])
@role_required('admin')
def dept():
    if request.method == 'POST':
        try:
            # Create new debt record
            new_debt = Debt(
                Borrower_name=request.form['Borrower_name'],
                dept_date=datetime.strptime(request.form['dept_date'], '%Y-%m-%d'),
                expected_return_date=datetime.strptime(request.form['expected_return_date'], '%Y-%m-%d'),
                dept_amount=float(request.form['dept_amount']),
                dept_type=request.form['dept_type'],
                dept_status=request.form['dept_status'],
                dept_description=request.form['dept_description']
            )
            
            db.session.add(new_debt)
            db.session.commit()
            flash('Debt record added successfully!', 'success')
            return redirect(url_for('dept'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error adding debt: {str(e)}', exc_info=True)
            flash('An error occurred while adding the debt record. Please try again.', 'error')
    
    # For both GET and POST (in case of error), show the debt list
    debts = Debt.query.order_by(Debt.dept_date.desc()).all()
    return render_template('dept.html', depts=debts)


@app.route('/transactions')
@role_required('admin')
def transactions():
    transactions = Transaction.query.all()
    return render_template('transanction.html', transactions=transactions)

@app.route('/benefits')
@role_required('admin')
def benefits():
    return "<h1>Benefits Page (Coming Soon)</h1>"

@app.route('/tithes')
@role_required('admin')
def tithes():
    return "<h1>Tithes Report Page (Coming Soon)</h1>"

@app.route('/withdrawals')
@role_required('admin')
def withdrawals():
    # Get status filter if provided
    status_filter = request.args.get('status', 'all')

    # Query based on status
    if status_filter == 'all':
        withdrawal_requests = WithdrawalRequest.query.all()
    else:
        withdrawal_requests = WithdrawalRequest.query.filter_by(status=status_filter).all()

    # Count withdrawals by status for the filter buttons
    status_counts = {
        'all': WithdrawalRequest.query.count(),
        'pending': WithdrawalRequest.query.filter_by(status='pending').count(),
        'approved': WithdrawalRequest.query.filter_by(status='approved').count(),
        'rejected': WithdrawalRequest.query.filter_by(status='rejected').count(),
    }

    return render_template(
        'withdraw.html', 
        withdrawals=withdrawal_requests,  # Changed from withdrawal_requests to withdrawals
        current_status=status_filter,
        status_counts=status_counts
    )

@app.route('/withdrawals/<int:withdrawal_id>/status', methods=['POST'])
@role_required('admin')
def update_withdrawal_status(withdrawal_id):
    withdrawal = WithdrawalRequest.query.get_or_404(withdrawal_id)
    new_status = request.form.get('status')
    
    if new_status not in ['pending', 'approved', 'rejected']:
        flash('Invalid status', 'error')
        return redirect(url_for('withdrawals'))
    
    try:
        withdrawal.status = new_status
        db.session.commit()
        flash(f'Withdrawal request {new_status} successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating withdrawal status: {str(e)}')
        flash('Failed to update withdrawal status', 'error')
    
    return redirect(url_for('withdrawals'))


@app.route('/client-history')
@role_required('admin')
def client_history():
    return "<h1>Client History Page (Coming Soon)</h1>"

@app.route('/wallet')
@role_required('admin')
def wallet():
    from models import User, Transaction, PayPALTransaction  # Assure-toi d'importer PayPALTransaction
    
    print("\n=== DEBUG WALLET ===")
    print(f"User ID: {session.get('user_id')}")
    print(f"Is admin: {hasattr(current_user, 'is_admin') and current_user.is_admin}")
    
    # Récupération des paramètres de filtre
    payment_method = request.args.get('payment_method')
    view = request.args.get('view', 'mobile_money')  # Valeur par défaut
    
    transactions = []
    paypal_transactions = []
    
    # === MOBILE MONEY ===
    if view != 'paypal':
        query = Transaction.query.order_by(Transaction.created_at.desc())

        # Filtrage par méthode de paiement
        if payment_method and payment_method.lower() != 'all':
            pm = payment_method.lower()
            if 'airtel' in pm:
                query = query.filter(Transaction.sending_method.ilike('%Airtel%'))
            elif 'orange' in pm:
                query = query.filter(Transaction.sending_method.ilike('%Orange%'))
            elif 'mpesa' in pm or 'm-pesa' in pm:
                query = query.filter(Transaction.sending_method.ilike('%M-Pesa%'))
            else:
                query = query.filter(Transaction.sending_method.ilike(f'%{payment_method}%'))

        transactions = query.all()
        print(f"✅ Found {len(transactions)} mobile money transactions")

        # Associer les utilisateurs
        for txn in transactions:
            txn.user = User.query.get(txn.user_id) if txn.user_id else type(
                'obj', (object,), {'image_url': url_for('static', filename='image/default-avatar.png')}
            )

        # Si requête AJAX pour mobile money
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify([
                {
                    'id': txn.id,
                    'amount': float(txn.amount or 0.0),
                    'status': txn.status,
                    'payment_method': txn.sending_method,
                    'created_at': txn.created_at.strftime('%b %d, %Y %I:%M %p') if txn.created_at else 'Unknown date',
                    'sender_name': txn.sender_name,
                    'receiver_name': txn.receiver_name,
                    'receiver_number': txn.receiver_number,
                    'fee': float(txn.fee or 0.0),
                    'total_amount': float(txn.total_amount or txn.amount or 0.0),
                    'user_image': txn.user.image_url if txn.user else url_for('static', filename='image/default-avatar.png')
                } for txn in transactions
            ])
    
    # === PAYPAL ===
    paypal_transactions = PayPALTransaction.query.order_by(PayPALTransaction.created_at.desc()).all()
    print(f"✅ Found {len(paypal_transactions)} PayPal transactions")

    # Si requête AJAX pour PayPal
    if view == 'paypal' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify([
            {
                'id': txn.id,
                'amount': float(txn.amount or 0.0),
                'status': txn.status,
                'payment_method': 'PayPal',
                'created_at': txn.created_at.strftime('%b %d, %Y %I:%M %p') if txn.created_at else 'Unknown date',
                'receiver_name': txn.receiver_name,
                'receiver_email': getattr(txn, 'receiver_email', ''),
                'fee': float(txn.fee or 0.0),
                'total_amount': float(txn.total_amount or txn.amount or 0.0)
            } for txn in paypal_transactions
        ])
    
    # === Rendu du template ===
    # Si view == paypal, transactions = vide, et paypal_transactions = rempli
    return render_template(
        'wallet.html',
        transactions=transactions if view != 'paypal' else [],
        paypal_transactions=paypal_transactions
    )


@app.route('/add-funds')
@role_required('admin')
def add_funds():
    return "<h1>Add Funds Page (Coming Soon)</h1>"

@app.route('/debts')
@role_required('admin')
def debts():
    return "<h1>Debts Page (Coming Soon)</h1>"

    
@app.route('/historique')
@login_required  # Require login to access this route
@role_required('employee')  # Require employee role

def historique():
    # Check if user is authenticated
    if not current_user.is_authenticated:
        flash('Please log in to view your transaction history.', 'warning')
        return redirect(url_for('login'))
    
    try:
        app.logger.info(f"Current user: {current_user.id} - {current_user.username}")
        
        # Get current user's transactions using user_id
        transactions = Transaction.query.filter(
            Transaction.user_id == current_user.id
        ).order_by(Transaction.created_at.desc()).all()
        
        app.logger.info(f"Found {len(transactions)} transactions for user ID {current_user.id}")
        
        # Get current user's withdrawal requests using email or phone number
        withdrawal_requests = WithdrawalRequest.query.filter(
            (WithdrawalRequest.receiver_email == current_user.email) |
            (WithdrawalRequest.sender_number == current_user.phone)
        ).order_by(WithdrawalRequest.created_at.desc()).all()
        
        app.logger.info(f"Found {len(withdrawal_requests)} withdrawal requests for user {current_user.email}")
         
        # Log some transaction details if any exist
        if transactions:
            for i, t in enumerate(transactions[:3]):  # Log first 3 transactions
                app.logger.info(f"Transaction {i+1}: {t.sender_name} -> {t.receiver_name} ${t.amount} ({t.status})")
        
        return render_template(
            'historique.html', 
            transactions=transactions, 
            withdrawalRequests=withdrawal_requests,
            session=session  # Make sure session is available in the template
        )
    except Exception as e:
        app.logger.error(f"Error in historique: {str(e)}", exc_info=True)
        flash('An error occurred while loading your transaction history.', 'error')
        return redirect(url_for('dashboard'))  

@app.route('/paypal')
@login_required
def paypal_page():
    return render_template('paypal.html')

@app.route('/api/paypal/transactions')
@login_required
def get_paypal_transactions():
    try:
        # Get query parameters for filtering
        status = request.args.get('status')
        search = request.args.get('search', '').lower()
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Base query
        query = PayPALTransaction.query
        
        # Apply filters
        if status and status.lower() != 'all':
            query = query.filter(PayPALTransaction.status == status.lower())
            
        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                (PayPALTransaction.sender_name.ilike(search_filter)) |
                (PayPALTransaction.receiver_name.ilike(search_filter)) |
                (PayPALTransaction.receiver_email.ilike(search_filter)) |
                (PayPALTransaction.transaction_id.ilike(f"%{search}%"))
            )
            
        if start_date:
            query = query.filter(PayPALTransaction.created_at >= start_date)
            
        if end_date:
            # Include the entire end date
            from datetime import datetime, timedelta
            end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(PayPALTransaction.created_at < end)
        
        # Order by most recent first
        transactions = query.order_by(desc(PayPALTransaction.created_at)).all()
        
        # Convert to list of dictionaries
        result = []
        for t in transactions:
            result.append({
                'id': t.id,
                'sender_name': t.sender_name,
                'receiver_name': t.receiver_name,
                'receiver_email': t.receiver_email,
                'amount': float(t.amount) if t.amount else 0.0,
                'fee': float(t.fee) if t.fee is not None else 0.0,
                'total_amount': float(t.total_amount) if t.total_amount else 0.0,
                'receiver_number': t.receiver_number,
                'status': t.status,
                'created_at': t.created_at.isoformat() if t.created_at else None,
                'updated_at': t.updated_at.isoformat() if t.updated_at else None,
                'transaction_id': t.transaction_id,
                'payout_item_id': t.payout_item_id
            })
            
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error in get_paypal_transactions: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while fetching transactions"}), 500
@app.route('/paypalAlltransactionView')
@login_required
def paypalAlltransactionView():
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Get filter parameters
        status = request.args.get('status', 'all')
        search = request.args.get('search', '').strip()
        
        # Build the base query, excluding batch_denied transactions
        query = PayPALTransaction.query.filter(PayPALTransaction.status != 'batch_denied')
        
        # Apply filters
        if status and status.lower() != 'all':
            query = query.filter(PayPALTransaction.status == status.upper())
            
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                (PayPALTransaction.transaction_id.ilike(search_term)) |
                (PayPALTransaction.sender_name.ilike(search_term)) |
                (PayPALTransaction.receiver_name.ilike(search_term)) |
                (PayPALTransaction.receiver_email.ilike(search_term))
            )
        
        # Order by most recent first and paginate
        transactions = query.order_by(
            PayPALTransaction.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        return render_template(
            'paypaleAdminView.html',
            transactions=transactions.items,
            pagination=transactions,
            current_status=status,
            current_search=search
        )
        
    except Exception as e:
        app.logger.error(f"Error in paypalAlltransactionView: {str(e)}")
        flash('An error occurred while loading transactions.', 'error')
        return render_template('paypaleAdminView.html', transactions=[])
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        # Define the uploads directory
        uploads_dir = os.path.join(app.root_path, 'static/uploads')
        
        # Create the directory if it doesn't exist
        os.makedirs(uploads_dir, exist_ok=True)
        
        # Check if file exists
        full_path = os.path.join(uploads_dir, filename)
        if not os.path.exists(full_path):
            app.logger.error(f"File not found: {full_path}")
            return "File not found", 404
            
        # Serve the file
        return send_from_directory(uploads_dir, filename)
        
    except Exception as e:
        app.logger.error(f"Error serving file {filename}: {str(e)}")
        return str(e), 500


@app.route('/logout')
@login_required  # This ensures only logged-in users can access this route
def logout():
    logout_user()  # Log the user out with Flask-Login
    session.clear()  # Clear the session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))





# Run the app
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({'error': 'CSRF token is missing or invalid'}), 400

@app.route('/test-email')
def test_email():
    try:
        msg = Message('Test Email from JazzyAgency',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=['jbmuisha@gmail.com'])
        msg.body = 'This is a test email from your JazzyAgency application.'
        mail.send(msg)
        return 'Test email sent successfully!'
    except Exception as e:
        return f'Error sending email: {str(e)}'

if __name__ == '__main__':
    with app.app_context():
        # Create database tables if they don't exist
        db.create_all()
    # Run the application
    app.run(debug=True ,port=5000)
