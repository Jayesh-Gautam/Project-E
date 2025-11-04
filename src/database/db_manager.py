"""
Database manager for user accounts and messages
"""

import sqlite3
import bcrypt
import json
from datetime import datetime
from typing import Optional, List, Dict

class DatabaseManager:
    def __init__(self, db_path: str = "secure_chat.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                public_key TEXT,
                private_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                recipient_id INTEGER,
                message_data BLOB,
                is_global BOOLEAN DEFAULT 1,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (recipient_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_user(self, username: str, password: str, totp_secret: str, 
                   public_key: dict, private_key: list) -> bool:
        """Create a new user account"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Hash password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, totp_secret, public_key, private_key)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, totp_secret, 
                  json.dumps(public_key), json.dumps(private_key)))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user with username and password"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            return {
                'id': user[0],
                'username': user[1],
                'totp_secret': user[3],
                'public_key': json.loads(user[4]),
                'private_key': json.loads(user[5])
            }
        return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user information by username"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, public_key FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'public_key': json.loads(user[2])
            }
        return None
    
    def store_message(self, sender_id: int, recipient_id: Optional[int], 
                     encrypted_data: bytes, is_global: bool = True):
        """Store encrypted message"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO messages (sender_id, recipient_id, message_data, is_global)
            VALUES (?, ?, ?, ?)
        ''', (sender_id, recipient_id, encrypted_data, is_global))
        
        conn.commit()
        conn.close()
    
    def get_messages(self, user_id: int, limit: int = 50) -> List[Dict]:
        """Get messages for user (global + direct messages)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT m.id, m.sender_id, m.recipient_id, m.message_data, 
                   m.is_global, m.timestamp, u.username as sender_username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.is_global = 1 OR m.recipient_id = ? OR m.sender_id = ?
            ORDER BY m.timestamp DESC
            LIMIT ?
        ''', (user_id, user_id, limit))
        
        messages = cursor.fetchall()
        conn.close()
        
        return [{
            'id': msg[0],
            'sender_id': msg[1],
            'recipient_id': msg[2],
            'message_data': msg[3],
            'is_global': bool(msg[4]),
            'timestamp': msg[5],
            'sender_username': msg[6]
        } for msg in messages]
    
    def get_all_users(self) -> List[Dict]:
        """Get list of all users for tagging"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username FROM users')
        users = cursor.fetchall()
        conn.close()
        
        return [{'id': user[0], 'username': user[1]} for user in users]