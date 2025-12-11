import os
import sys
from pathlib import Path
import sqlite3
from flask import Flask
from models import db, User

# Get the absolute path to the instance directory
BASE_DIR = Path(__file__).parent
INSTANCE_DIR = BASE_DIR / 'instance'

# Ensure instance directory exists
INSTANCE_DIR.mkdir(exist_ok=True)

# Database paths
SOURCE_DB = str(INSTANCE_DIR / 'users.db')
TARGET_DB = str(INSTANCE_DIR / 'app.db')

# Create a temporary Flask app to use SQLAlchemy
temp_app = Flask(__name__)
temp_app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{TARGET_DB}'
temp_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(temp_app)

def check_database_file(db_path, description):
    """Check if database file exists and is accessible."""
    if not os.path.exists(db_path):
        print(f"Error: {description} database not found at {db_path}")
        return False
    if not os.access(db_path, os.R_OK | os.W_OK):
        print(f"Error: No permission to access {description} database at {db_path}")
        return False
    return True

def merge_databases():
    # Check if source database exists
    if not check_database_file(SOURCE_DB, 'source'):
        return
    
    # Check if target database exists
    if not check_database_file(TARGET_DB, 'target'):
        return
    
    with temp_app.app_context():
        try:
            # Connect to the source database (users.db)
            source_conn = sqlite3.connect(f'file:{SOURCE_DB}?mode=ro', uri=True)
            source_cursor = source_conn.cursor()
            
            # Get all users from source
            source_cursor.execute('SELECT * FROM users')
            users = source_cursor.fetchall()
            
            if not users:
                print("No users found in the source database.")
                return
                
            # Get column names
            source_cursor.execute('PRAGMA table_info(users)')
            columns = [column[1] for column in source_cursor.fetchall()]
            
            # For each user in the source database
            for user_data in users:
                user_dict = dict(zip(columns, user_data))
                
                # Check if user already exists in the target database
                existing_user = User.query.get(user_dict['id'])
                
                if not existing_user:
                    # Create a new user in the target database
                    user = User(
                        id=user_dict['id'],
                        username=user_dict['username'],
                        email=user_dict['email'],
                        password_hash=user_dict['password_hash'],
                        role=user_dict.get('role', 'employee'),
                        is_active=bool(user_dict.get('is_active', True)),
                        is_verified=bool(user_dict.get('is_verified', False)),
                        created_at=user_dict.get('created_at'),
                        last_login=user_dict.get('last_login')
                    )
                    db.session.add(user)
                    print(f"Added user: {user.username} ({user.email})")
            
            # Commit all changes
            db.session.commit()
            print("\nDatabase merge completed successfully!")
            print(f"Source database: {SOURCE_DB}")
            print(f"Target database: {TARGET_DB}")
            
        except sqlite3.Error as e:
            print(f"\nSQLite error: {e}")
            db.session.rollback()
        except Exception as e:
            print(f"\nError during database merge: {e}")
            db.session.rollback()
        finally:
            # Close connections
            if 'source_conn' in locals():
                source_conn.close()
            print("\nDatabase connections closed.")

if __name__ == '__main__':
    print("Starting database merge...")
    print(f"Source: {SOURCE_DB}")
    print(f"Target: {TARGET_DB}\n")
    
    # Verify both databases exist
    if not os.path.exists(SOURCE_DB) or not os.path.exists(TARGET_DB):
        print("Error: One or both database files not found.")
        if not os.path.exists(SOURCE_DB):
            print(f"- Source database not found: {SOURCE_DB}")
        if not os.path.exists(TARGET_DB):
            print(f"- Target database not found: {TARGET_DB}")
        sys.exit(1)
    
    merge_databases()
