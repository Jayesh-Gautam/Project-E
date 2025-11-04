"""
Main application window with PyQt5
"""

import sys
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTextEdit, QLineEdit, QPushButton, QLabel, 
                            QStackedWidget, QListWidget, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

from .login_window import LoginWindow
from .chat_widget import ChatWidget
from src.database.db_manager import DatabaseManager
from src.crypto.lattice_crypto import LatticeCrypto

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db_manager = DatabaseManager()
        self.crypto = LatticeCrypto()
        self.current_user = None
        
        self.setWindowTitle("SecureChat - Lattice Encrypted Messaging")
        self.setGeometry(100, 100, 1000, 700)
        
        # Initialize UI
        self.init_ui()
        
        # Show login first
        self.show_login()
    
    def init_ui(self):
        """Initialize the main UI components"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create stacked widget for different views
        self.stacked_widget = QStackedWidget()
        
        # Login window
        self.login_window = LoginWindow(self.db_manager, self.crypto)
        self.login_window.login_successful.connect(self.on_login_success)
        
        # Chat window
        self.chat_widget = ChatWidget(self.db_manager, self.crypto)
        
        # Add widgets to stack
        self.stacked_widget.addWidget(self.login_window)
        self.stacked_widget.addWidget(self.chat_widget)
        
        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.stacked_widget)
        central_widget.setLayout(layout)
    
    def show_login(self):
        """Show login window"""
        self.stacked_widget.setCurrentWidget(self.login_window)
    
    def on_login_success(self, user_data):
        """Handle successful login"""
        self.current_user = user_data
        self.chat_widget.set_current_user(user_data)
        self.stacked_widget.setCurrentWidget(self.chat_widget)
        
        # Update window title with username
        self.setWindowTitle(f"SecureChat - {user_data['username']}")
    
    def logout(self):
        """Logout and return to login screen"""
        self.current_user = None
        self.chat_widget.clear_chat()
        self.show_login()
        self.setWindowTitle("SecureChat - Lattice Encrypted Messaging")