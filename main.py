#!/usr/bin/env python3
"""
Secure Messaging App with Lattice-based Cryptography
Main application entry point
"""

import sys
import asyncio
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QThread
from src.ui.main_window import MainWindow
from src.core.client import MessageClient

def main():
    app = QApplication(sys.argv)
    
    # Initialize the main window
    main_window = MainWindow()
    main_window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()