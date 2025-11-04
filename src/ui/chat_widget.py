"""
Main chat interface
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, 
                            QLineEdit, QPushButton, QListWidget, QSplitter,
                            QLabel, QMessageBox, QListWidgetItem)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QTextCursor
import re
from datetime import datetime

class ChatWidget(QWidget):
    def __init__(self, db_manager, crypto):
        super().__init__()
        self.db_manager = db_manager
        self.crypto = crypto
        self.current_user = None
        
        self.init_ui()
        
        # Timer for refreshing messages
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_messages)
        self.refresh_timer.start(2000)  # Refresh every 2 seconds
    
    def init_ui(self):
        """Initialize chat UI"""
        layout = QHBoxLayout()
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - User list
        left_panel = self.create_user_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Chat
        right_panel = self.create_chat_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([200, 600])
        
        layout.addWidget(splitter)
        self.setLayout(layout)
    
    def create_user_panel(self):
        """Create user list panel"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Online Users")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title)
        
        # User list
        self.user_list = QListWidget()
        layout.addWidget(self.user_list)
        
        # Logout button
        logout_btn = QPushButton("Logout")
        logout_btn.clicked.connect(self.logout)
        layout.addWidget(logout_btn)
        
        widget.setLayout(layout)
        return widget
    
    def create_chat_panel(self):
        """Create main chat panel"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Chat display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setFont(QFont("Consolas", 10))
        layout.addWidget(self.chat_display)
        
        # Message input area
        input_layout = QHBoxLayout()
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message... Use @username to send private message")
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)
        
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(send_btn)
        
        layout.addLayout(input_layout)
        
        # Help text
        help_text = QLabel("💡 Tip: Use @username to send a private message that only they can see")
        help_text.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(help_text)
        
        widget.setLayout(layout)
        return widget
    
    def set_current_user(self, user_data):
        """Set current logged in user"""
        self.current_user = user_data
        self.refresh_users()
        self.refresh_messages()
    
    def refresh_users(self):
        """Refresh user list"""
        if not self.current_user:
            return
        
        users = self.db_manager.get_all_users()
        self.user_list.clear()
        
        for user in users:
            if user['username'] != self.current_user['username']:
                item = QListWidgetItem(f"@{user['username']}")
                self.user_list.addItem(item)
    
    def refresh_messages(self):
        """Refresh chat messages"""
        if not self.current_user:
            return
        
        messages = self.db_manager.get_messages(self.current_user['id'])
        
        # Clear and rebuild chat display
        self.chat_display.clear()
        
        for msg in reversed(messages):  # Show oldest first
            try:
                # Decrypt message
                decrypted_text = self.crypto.decrypt_message(
                    msg['message_data'], 
                    self.current_user['private_key']
                )
                
                # Format timestamp
                timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%H:%M:%S")
                
                # Check if message is visible to current user
                if msg['is_global']:
                    # Global message - check if it's tagged to someone else
                    if self.is_message_tagged_to_other(decrypted_text):
                        continue  # Skip messages tagged to others
                    
                    self.chat_display.append(f"[{timestamp}] {msg['sender_username']}: {decrypted_text}")
                else:
                    # Private message
                    if (msg['recipient_id'] == self.current_user['id'] or 
                        msg['sender_id'] == self.current_user['id']):
                        
                        prefix = "🔒 Private" if msg['recipient_id'] == self.current_user['id'] else "🔒 To"
                        self.chat_display.append(f"[{timestamp}] {prefix} {msg['sender_username']}: {decrypted_text}")
                
            except Exception as e:
                # Skip messages that can't be decrypted
                continue
        
        # Scroll to bottom
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.chat_display.setTextCursor(cursor)
    
    def is_message_tagged_to_other(self, message_text):
        """Check if message is tagged to someone other than current user"""
        # Find @username mentions
        mentions = re.findall(r'@(\w+)', message_text)
        
        if mentions:
            # If there are mentions and current user is not mentioned, hide message
            return self.current_user['username'] not in mentions
        
        return False  # No mentions, show to everyone
    
    def send_message(self):
        """Send a message"""
        message_text = self.message_input.text().strip()
        if not message_text or not self.current_user:
            return
        
        try:
            # Check for private message (@username)
            mentions = re.findall(r'@(\w+)', message_text)
            
            if mentions:
                # Send as tagged message (still global but only visible to mentioned users)
                recipient_user = self.db_manager.get_user_by_username(mentions[0])
                if recipient_user:
                    # Encrypt with recipient's public key for private message
                    encrypted_data = self.crypto.encrypt_message(
                        message_text, 
                        recipient_user['public_key']
                    )
                    
                    # Store as private message
                    self.db_manager.store_message(
                        self.current_user['id'],
                        recipient_user['id'],
                        encrypted_data,
                        is_global=False
                    )
                else:
                    QMessageBox.warning(self, "Error", f"User @{mentions[0]} not found")
                    return
            else:
                # Global message - encrypt with current user's public key
                encrypted_data = self.crypto.encrypt_message(
                    message_text, 
                    self.current_user['public_key']
                )
                
                self.db_manager.store_message(
                    self.current_user['id'],
                    None,
                    encrypted_data,
                    is_global=True
                )
            
            # Clear input
            self.message_input.clear()
            
            # Refresh messages immediately
            self.refresh_messages()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send message: {str(e)}")
    
    def logout(self):
        """Logout user"""
        self.current_user = None
        self.clear_chat()
        # Signal parent to show login
        self.parent().parent().parent().logout()
    
    def clear_chat(self):
        """Clear chat display"""
        self.chat_display.clear()
        self.user_list.clear()
        self.message_input.clear()