"""
Login and registration window
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, 
                            QPushButton, QLabel, QTabWidget, QMessageBox,
                            QTextEdit)
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QPixmap, QFont
import base64
from io import BytesIO
from PIL import Image

from src.auth.authenticator import TwoFactorAuth

class LoginWindow(QWidget):
    login_successful = pyqtSignal(dict)
    
    def __init__(self, db_manager, crypto):
        super().__init__()
        self.db_manager = db_manager
        self.crypto = crypto
        self.two_fa = TwoFactorAuth()
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize login UI"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("SecureChat")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 24, QFont.Bold))
        layout.addWidget(title)
        
        subtitle = QLabel("Lattice-based End-to-End Encrypted Messaging")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setFont(QFont("Arial", 12))
        layout.addWidget(subtitle)
        
        # Tab widget for login/register
        self.tab_widget = QTabWidget()
        
        # Login tab
        login_tab = self.create_login_tab()
        self.tab_widget.addTab(login_tab, "Login")
        
        # Register tab
        register_tab = self.create_register_tab()
        self.tab_widget.addTab(register_tab, "Register")
        
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)
    
    def create_login_tab(self):
        """Create login tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Username
        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("Username")
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.login_username)
        
        # Password
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Password")
        self.login_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.login_password)
        
        # 2FA Token
        self.login_token = QLineEdit()
        self.login_token.setPlaceholderText("2FA Token (6 digits)")
        layout.addWidget(QLabel("2FA Token:"))
        layout.addWidget(self.login_token)
        
        # Login button
        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self.handle_login)
        layout.addWidget(login_btn)
        
        widget.setLayout(layout)
        return widget
    
    def create_register_tab(self):
        """Create registration tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Username
        self.reg_username = QLineEdit()
        self.reg_username.setPlaceholderText("Choose username")
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.reg_username)
        
        # Password
        self.reg_password = QLineEdit()
        self.reg_password.setPlaceholderText("Choose password")
        self.reg_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.reg_password)
        
        # Confirm password
        self.reg_confirm = QLineEdit()
        self.reg_confirm.setPlaceholderText("Confirm password")
        self.reg_confirm.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Confirm Password:"))
        layout.addWidget(self.reg_confirm)
        
        # Generate 2FA button
        generate_btn = QPushButton("Generate 2FA Setup")
        generate_btn.clicked.connect(self.generate_2fa)
        layout.addWidget(generate_btn)
        
        # QR Code display
        self.qr_label = QLabel("QR Code will appear here")
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumHeight(200)
        self.qr_label.setStyleSheet("border: 1px solid gray;")
        layout.addWidget(self.qr_label)
        
        # 2FA verification
        self.reg_token = QLineEdit()
        self.reg_token.setPlaceholderText("Enter 2FA token to verify setup")
        layout.addWidget(QLabel("Verify 2FA Token:"))
        layout.addWidget(self.reg_token)
        
        # Register button
        register_btn = QPushButton("Register")
        register_btn.clicked.connect(self.handle_register)
        layout.addWidget(register_btn)
        
        widget.setLayout(layout)
        return widget
    
    def generate_2fa(self):
        """Generate 2FA QR code"""
        username = self.reg_username.text().strip()
        if not username:
            QMessageBox.warning(self, "Error", "Please enter a username first")
            return
        
        try:
            secret = self.two_fa.generate_secret(username)
            qr_data = self.two_fa.get_qr_code(username)
            
            # Convert base64 to QPixmap
            qr_bytes = base64.b64decode(qr_data)
            pixmap = QPixmap()
            pixmap.loadFromData(qr_bytes)
            
            # Scale and display
            scaled_pixmap = pixmap.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.qr_label.setPixmap(scaled_pixmap)
            
            QMessageBox.information(self, "2FA Setup", 
                                  "Scan the QR code with your authenticator app, then enter a token to verify.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate 2FA: {str(e)}")
    
    def handle_login(self):
        """Handle login attempt"""
        username = self.login_username.text().strip()
        password = self.login_password.text()
        token = self.login_token.text().strip()
        
        if not all([username, password, token]):
            QMessageBox.warning(self, "Error", "Please fill in all fields")
            return
        
        # Authenticate user
        user_data = self.db_manager.authenticate_user(username, password)
        if not user_data:
            QMessageBox.warning(self, "Error", "Invalid username or password")
            return
        
        # Verify 2FA token
        if not self.two_fa.verify_token(token, user_data['totp_secret']):
            QMessageBox.warning(self, "Error", "Invalid 2FA token")
            return
        
        # Login successful
        self.login_successful.emit(user_data)
        
        # Clear fields
        self.login_username.clear()
        self.login_password.clear()
        self.login_token.clear()
    
    def handle_register(self):
        """Handle registration"""
        username = self.reg_username.text().strip()
        password = self.reg_password.text()
        confirm = self.reg_confirm.text()
        token = self.reg_token.text().strip()
        
        if not all([username, password, confirm, token]):
            QMessageBox.warning(self, "Error", "Please fill in all fields")
            return
        
        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return
        
        if not self.two_fa.secret:
            QMessageBox.warning(self, "Error", "Please generate 2FA setup first")
            return
        
        # Verify 2FA token
        if not self.two_fa.verify_token(token):
            QMessageBox.warning(self, "Error", "Invalid 2FA token")
            return
        
        # Generate crypto keys
        keypair = self.crypto.generate_keypair()
        
        # Create user
        success = self.db_manager.create_user(
            username, password, self.two_fa.secret,
            keypair['public'], keypair['private']
        )
        
        if success:
            QMessageBox.information(self, "Success", "Account created successfully! You can now login.")
            self.tab_widget.setCurrentIndex(0)  # Switch to login tab
            
            # Clear registration fields
            self.reg_username.clear()
            self.reg_password.clear()
            self.reg_confirm.clear()
            self.reg_token.clear()
            self.qr_label.clear()
            self.qr_label.setText("QR Code will appear here")
            self.two_fa.secret = None
        else:
            QMessageBox.warning(self, "Error", "Username already exists")