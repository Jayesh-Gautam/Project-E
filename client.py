"""
Secure Chat Client - Modern UI (v2 - 2-Column Layout)
This file replaces the original client.py with a new 2-column UI.
The first column is a QStackedWidget that switches between
the Group list and the Member list.
"""
import sys
import asyncio
import websockets
import json
import qrcode
import io
import os
import datetime # Added for timestamps

# Import our security module
import security

# --- Pre-import check ---
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTextEdit, QLineEdit, QPushButton, QLabel, QStackedWidget,
        QFormLayout, QMessageBox, QListWidget, QListWidgetItem,
        QSplitter, QFrame
    )
    from PyQt6.QtCore import QThread, pyqtSignal, Qt, QSize
    from PyQt6.QtGui import QPixmap, QImage, QFont, QIcon, QFontDatabase, QColor
except ImportError as e:
    print("--- FATAL ERROR ---")
    print(f"Could not import PyQt6. Error: {e}")
    print("Please make sure you are in your activated virtual environment (.venv)")
    print("and you have run: pip install -r requirements.txt")
    print("---------------------")
    sys.exit(1)
# --- End of check ---

from asyncqt import QEventLoop

# --- Key Management (Unchanged from original client.py) ---
PRIVATE_KEY_FILE = "client_private_key.pem"
g_private_key = None
g_public_key = None
g_public_key_pem = None
g_public_key_cache = {}  # { "username": "--- BEGIN PUBLIC KEY ---..." }

def load_or_generate_keys_sync():
    global g_private_key, g_public_key, g_public_key_pem
    if os.path.exists(PRIVATE_KEY_FILE):
        print(f"Loading private key from {PRIVATE_KEY_FILE}...")
        try:
            with open(PRIVATE_KEY_FILE, 'r') as f:
                pem_data = f.read()
            g_private_key = security.load_private_key(pem_data)
            g_public_key = g_private_key.public_key()
        except Exception as e:
            print(f"Error loading key, generating new one: {e}")
            os.remove(PRIVATE_KEY_FILE)
            load_or_generate_keys_sync()
            return
    else:
        print("No private key found, generating a new one...")
        g_private_key, g_public_key = security.generate_key_pair()
        pem_data = security.serialize_private_key(g_private_key)
        try:
            with open(PRIVATE_KEY_FILE, 'w') as f:
                f.write(pem_data)
            print(f"Saved new private key to {PRIVATE_KEY_FILE}")
        except Exception as e:
            print(f"FATAL: Could not write private key file: {e}")
            sys.exit(1)
    g_public_key_pem = security.serialize_public_key(g_public_key)

# --- WebSocket Client Thread (Unchanged) ---
class WebSocketClientThread(QThread):
    # Signals for login/signup
    login_success = pyqtSignal(str)
    login_fail = pyqtSignal(str)
    signup_success_needs_2fa = pyqtSignal(str, str)  # uri, secret
    login_needs_2fa = pyqtSignal()
    signup_complete = pyqtSignal(str)  # success message
    signup_fail = pyqtSignal(str)

    # Signals for chat
    message_received = pyqtSignal(str, str, str) # sender, target, decrypted_message
    connection_status = pyqtSignal(str)
    
    # *** NEW SIGNAL FOR THE TERMINAL ***
    crypto_log = pyqtSignal(str)

    # Signals for groups
    my_groups_list = pyqtSignal(list)
    join_group_fail = pyqtSignal(str)
    create_group_fail = pyqtSignal(str)
    select_group_success = pyqtSignal(str) # group_code
    group_member_list = pyqtSignal(list)
    public_key_response = pyqtSignal(str, str)  # username, public_key_pem

    def __init__(self, uri):
        super().__init__()
        self.uri = uri
        self.loop = None
        self.websocket = None
        self.running = True
        self.send_queue = None
        self.my_username = None
        self.current_group_code = None

    def run(self):
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.send_queue = asyncio.Queue()
            self.loop.run_until_complete(self.connect_and_listen())
        except Exception as e:
            print(f"Thread loop error: {e}")
        finally:
            self.connection_status.emit("Disconnected.")
            if self.loop:
                self.loop.close()

    async def connect_and_listen(self):
        self.connection_status.emit("Connecting...")
        try:
            async with websockets.connect(self.uri) as ws:
                self.websocket = ws
                self.connection_status.emit("Connected. Please log in.")
                consumer_task = asyncio.create_task(self.consumer_handler())
                producer_task = asyncio.create_task(self.producer_handler())
                await asyncio.gather(consumer_task, producer_task)
        except (websockets.exceptions.ConnectionClosedError, asyncio.CancelledError):
            self.connection_status.emit("Connection lost.")
        except Exception as e:
            self.connection_status.emit(f"Error: {e}")

    async def consumer_handler(self):
        """Listens for messages from the server."""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message)
                    msg_type = data.get("type")

                    if msg_type == "login_success":
                        self.my_username = data.get("username")
                        self.login_success.emit(self.my_username)
                    elif msg_type == "login_fail":
                        self.login_fail.emit(data.get("error", "Unknown login error"))
                    elif msg_type == "signup_fail":
                        self.signup_fail.emit(data.get("error", "Unknown signup error"))
                    elif msg_type == "chat_message":
                        self.handle_encrypted_chat(data) # Modified
                    elif msg_type == "my_groups_list":
                        self.my_groups_list.emit(data.get("groups", []))
                    elif msg_type == "join_group_fail":
                        self.join_group_fail.emit(data.get("error", "Failed to join"))
                    elif msg_type == "create_group_fail":
                        self.create_group_fail.emit(data.get("error", "Failed to create"))
                    elif msg_type == "select_group_success":
                        self.current_group_code = data.get("group_code")
                        self.select_group_success.emit(self.current_group_code)
                    elif msg_type == "signup_success_needs_2fa":
                        self.signup_success_needs_2fa.emit(
                            data.get("provisioning_uri"),
                            data.get("secret")
                        )
                    elif msg_type == "login_needs_2fa":
                        self.login_needs_2fa.emit()
                    elif msg_type == "signup_complete":
                        self.signup_complete.emit(data.get("message"))
                    elif msg_type == "group_member_list":
                        self.group_member_list.emit(data.get("members", []))
                    elif msg_type == "public_key_response":
                        self.public_key_response.emit(
                            data.get("username"),
                            data.get("public_key")
                        )
                    elif msg_type == "error":
                        self.login_fail.emit(f"Server error: {data.get('message')}")
                except json.JSONDecodeError:
                    self.crypto_log.emit(f"[RAW] {message}")
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            print(f"Consumer error: {e}")

    def handle_encrypted_chat(self, data: dict):
        """NEW: Decrypts an incoming chat message and emits logs."""
        try:
            encrypted_content = data.get("content")
            sender_id = data.get("sender_id")
            target = data.get("target")

            # Ignore our own messages
            if sender_id == self.my_username:
                return

            self.crypto_log.emit(f"[RECV] From: {sender_id} (Target: {target})")
            self.crypto_log.emit(f"[CIPHERTEXT] {encrypted_content[:30]}...")

            decrypted_message = None
            crypto_type = "UNKNOWN"

            if target == "Everyone":
                if not self.current_group_code: return
                key = security.derive_group_key(self.current_group_code)
                decrypted_message = security.decrypt_with_group_key(key, encrypted_content)
                crypto_type = "AES-GCM"

            elif target == self.my_username:
                # It's a DM for me
                decrypted_message = security.decrypt_with_private_key(g_private_key, encrypted_content)
                crypto_type = "RSA-OAEP" # Based on security.py
            
            else:
                # It's a DM for someone else
                decrypted_message = f"[Encrypted DM for {target}]"
                crypto_type = "SKIPPED"
                self.crypto_log.emit(f"[DECRYPT:{crypto_type}] Message not intended for this user.")
                # We still emit this so the UI can show a placeholder
                self.message_received.emit(sender_id, target, decrypted_message)
                return

            if decrypted_message is None:
                self.crypto_log.emit(f"[DECRYPT:FAILED] Key or content error.")
                return

            self.crypto_log.emit(f"[DECRYPT:{crypto_type}] -> {decrypted_message}")
            self.message_received.emit(sender_id, target, decrypted_message)

        except Exception as e:
            print(f"Error in handle_encrypted_chat: {e}")
            self.crypto_log.emit(f"[DECRYPT:ERROR] {e}")

    async def producer_handler(self):
        """Listens for messages from the UI to send to the server."""
        try:
            while self.running:
                message_dict = await self.send_queue.get()
                if message_dict is None:
                    break
                await self.websocket.send(json.dumps(message_dict))
        except websockets.exceptions.ConnectionClosed:
            self.connection_status.emit("Connection lost (producer).")
        except Exception as e:
            print(f"Producer error: {e}")

    def send_message(self, message_dict):
        if self.loop and self.send_queue is not None:
            self.loop.call_soon_threadsafe(self.send_queue.put_nowait, message_dict)

    def stop(self):
        self.running = False
        if self.loop and self.send_queue is not None:
            self.loop.call_soon_threadsafe(self.send_queue.put_nowait, None)
        self.quit()
        self.wait(2000)
        if self.isRunning():
            self.terminate()


# --- Login/Signup Pages (Unchanged) ---
class LoginPage(QWidget):
    def __init__(self, client_thread):
        super().__init__()
        self.client_thread = client_thread
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.title_label = QLabel("Project-E Secure Chat")
        self.title_label.setObjectName("TitleLabel")
        layout.addWidget(self.title_label, alignment=Qt.AlignmentFlag.AlignCenter)

        form_layout = QFormLayout()
        form_layout.setContentsMargins(50, 20, 50, 20)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        form_layout.addRow("Username:", self.username_input)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Password:", self.password_input)
        layout.addLayout(form_layout)
        
        button_layout = QHBoxLayout()
        self.login_button = QPushButton("Login")
        self.login_button.setObjectName("PrimaryButton")
        self.login_button.clicked.connect(self.on_login)
        button_layout.addWidget(self.login_button)
        
        self.signup_button = QPushButton("Sign Up")
        self.signup_button.clicked.connect(self.on_signup)
        button_layout.addWidget(self.signup_button)
        layout.addLayout(button_layout)
        
        self.status_label = QLabel("Enter credentials")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setObjectName("StatusLabel")
        layout.addWidget(self.status_label)
        
        self.global_status_label = QLabel("Loading keys...")
        self.global_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.global_status_label.setObjectName("GlobalStatusLabel")
        layout.addWidget(self.global_status_label)

    def on_login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        if username and password:
            self.status_label.setText("Logging in...")
            self.client_thread.send_message({"type": "login", "username": username, "password": password})

    def on_signup(self):
        username = self.username_input.text()
        password = self.password_input.text()
        if username and password:
            if not g_public_key_pem:
                self.status_label.setText("Error: Public key not loaded.")
                return
            self.status_label.setText("Signing up...")
            self.client_thread.send_message({
                "type": "signup",
                "username": username,
                "password": password,
                "public_key": g_public_key_pem
            })

class TwoFAPage(QWidget):
    def __init__(self, client_thread):
        super().__init__()
        self.client_thread = client_thread
        self.mode = ""  # "signup" or "login"
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label = QLabel("2-Factor Authentication")
        self.title_label.setObjectName("TitleLabel")
        layout.addWidget(self.title_label, alignment=Qt.AlignmentFlag.AlignCenter)
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.qr_label)
        self.scan_label = QLabel("Scan this code with your authenticator app.")
        self.scan_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.scan_label)
        self.secret_label = QLineEdit()
        self.secret_label.setPlaceholderText("Or enter this secret key manually")
        self.secret_label.setReadOnly(True)
        layout.addWidget(self.secret_label)
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Enter 6-digit code")
        self.code_input.setMaxLength(6)
        self.code_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.code_input.returnPressed.connect(self.on_submit)
        layout.addWidget(self.code_input)
        self.submit_button = QPushButton("Verify")
        self.submit_button.setObjectName("PrimaryButton")
        self.submit_button.clicked.connect(self.on_submit)
        layout.addWidget(self.submit_button)
        self.status_label = QLabel()
        self.status_label.setObjectName("StatusLabel")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

    def set_mode(self, mode, provisioning_uri=None, secret=None):
        self.mode = mode
        self.status_label.setText("")
        self.code_input.clear()
        if mode == "signup":
            self.title_label.setText("Set Up 2-Factor Authentication")
            self.qr_label.show()
            self.scan_label.show()
            self.secret_label.show()
            self.secret_label.setText(secret)
            self.submit_button.setText("Verify & Complete Signup")
            try:
                qr_img = qrcode.make(provisioning_uri)
                qt_image = self._convert_pil_to_qt(qr_img)
                pixmap = QPixmap.fromImage(qt_image)
                self.qr_label.setPixmap(pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
            except Exception as e:
                print(f"Error generating QR code: {e}")
                self.qr_label.setText("Error generating QR code.")
        elif mode == "login":
            self.title_label.setText("Verify Your Identity")
            self.qr_label.hide()
            self.scan_label.hide()
            self.secret_label.hide()
            self.submit_button.setText("Verify Login")
            self.status_label.setText("Enter the code from your app.")

    def _convert_pil_to_qt(self, pil_img):
        pil_img = pil_img.convert("RGBA")
        data = pil_img.tobytes("raw", "RGBA")
        qimage = QImage(data, pil_img.size[0], pil_img.size[1], QImage.Format.Format_RGBA8888)
        return qimage

    def on_submit(self):
        code = self.code_input.text()
        if not code or len(code) != 6 or not code.isdigit():
            self.status_label.setText("Invalid code. Must be 6 digits.")
            return
        if self.mode == "signup":
            self.status_label.setText("Verifying...")
            self.client_thread.send_message({"type": "verify_totp_signup", "code": code})
        elif self.mode == "login":
            self.status_label.setText("Verifying...")
            self.client_thread.send_message({"type": "verify_totp_login", "code": code})

    def set_status(self, message):
        self.status_label.setText(message)


# --- NEW: Main 2-Column Application UI ---

class MainAppWidget(QWidget):
    """The main 2-column UI with a stacked sidebar."""
    
    # Emitted when the user types and hits send
    send_chat_message = pyqtSignal(str, str) # target_username, message_text
    # Emitted when the user selects a group
    group_selected = pyqtSignal(str) # group_code
    # Emitted to request a new group
    create_group = pyqtSignal(str) # group_name
    # Emitted to join a group
    join_group = pyqtSignal(str) # group_code
    # Emitted to request a public key
    request_public_key = pyqtSignal(str) # username

    def __init__(self, my_username: str):
        super().__init__()
        self.my_username = my_username
        self.current_group_code = None
        self.current_target_username = "Everyone" # Default target
        
        # --- Main Layout ---
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Column 1: Stacked Sidebar (Groups & Members) ---
        self.sidebar_stack = QStackedWidget()
        self.sidebar_stack.setObjectName("Sidebar")
        self.sidebar_stack.setFixedWidth(250)
        
        # --- Panel 1: Group List ---
        self.group_panel = QWidget()
        group_panel_layout = QVBoxLayout(self.group_panel)
        group_panel_layout.setContentsMargins(5, 5, 5, 5)
        group_panel_layout.setSpacing(5)

        self.group_list_widget = QListWidget()
        self.group_list_widget.setObjectName("GroupList")
        self.group_list_widget.itemDoubleClicked.connect(self.on_group_double_clicked)
        
        self.create_group_input = QLineEdit()
        self.create_group_input.setPlaceholderText("New group name...")
        self.create_group_button = QPushButton("Create Group")
        self.create_group_button.clicked.connect(self.on_create_group)
        
        self.join_group_input = QLineEdit()
        self.join_group_input.setPlaceholderText("Enter group code...")
        self.join_group_button = QPushButton("Join Group")
        self.join_group_button.clicked.connect(self.on_join_group)

        group_panel_layout.addWidget(QLabel("Your Groups (Double-click)"))
        group_panel_layout.addWidget(self.group_list_widget)
        group_panel_layout.addWidget(self.create_group_input)
        group_panel_layout.addWidget(self.create_group_button)
        group_panel_layout.addWidget(self.join_group_input)
        group_panel_layout.addWidget(self.join_group_button)
        
        # --- Panel 2: Member List ---
        self.member_panel = QWidget()
        member_panel_layout = QVBoxLayout(self.member_panel)
        member_panel_layout.setContentsMargins(5, 5, 5, 5)
        member_panel_layout.setSpacing(5)

        self.back_to_groups_button = QPushButton("← Back to Groups")
        self.back_to_groups_button.clicked.connect(self.show_group_list_panel)

        self.member_list_label = QLabel("Members")
        self.member_list_label.setObjectName("SidebarHeader")
        
        self.member_list_widget = QListWidget()
        self.member_list_widget.setObjectName("MemberList")
        self.member_list_widget.itemClicked.connect(self.on_member_clicked)

        member_panel_layout.addWidget(self.back_to_groups_button)
        member_panel_layout.addWidget(self.member_list_label)
        member_panel_layout.addWidget(self.member_list_widget)

        # Add panels to stack
        self.sidebar_stack.addWidget(self.group_panel)     # index 0
        self.sidebar_stack.addWidget(self.member_panel)    # index 1
        
        main_layout.addWidget(self.sidebar_stack)

        # --- Column 2: Chat & Terminal ---
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setObjectName("ChatDisplay")

        self.terminal_display = QTextEdit()
        self.terminal_display.setReadOnly(True)
        self.terminal_display.setObjectName("SecurityTerminal")
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(10)
        self.terminal_display.setFont(font)
        
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.addWidget(self.chat_display)
        self.splitter.addWidget(self.terminal_display)
        self.splitter.setSizes([700, 300]) # 70% chat, 30% terminal

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message... (@Everyone is default)")
        self.message_input.returnPressed.connect(self.on_send_clicked)
        
        self.send_button = QPushButton("Send")
        self.send_button.setObjectName("PrimaryButton")
        self.send_button.clicked.connect(self.on_send_clicked)

        message_input_layout = QHBoxLayout()
        message_input_layout.addWidget(self.message_input)
        message_input_layout.addWidget(self.send_button)
        
        chat_area_layout = QVBoxLayout()
        chat_area_layout.setContentsMargins(5, 5, 5, 5)
        self.chat_area_header = QLabel("Select a group to start chatting")
        self.chat_area_header.setObjectName("ChatHeader")
        chat_area_layout.addWidget(self.chat_area_header)
        chat_area_layout.addWidget(self.splitter)
        chat_area_layout.addLayout(message_input_layout)

        chat_area_container = QWidget()
        chat_area_container.setObjectName("ChatArea")
        chat_area_container.setLayout(chat_area_layout)
        main_layout.addWidget(chat_area_container)

    def on_send_clicked(self):
        text = self.message_input.text()
        if not text or not self.current_group_code:
            return
        
        # current_target_username is set by on_member_clicked
        self.send_chat_message.emit(self.current_target_username, text)
        self.message_input.clear()

    def on_group_double_clicked(self, item: QListWidgetItem):
        group_code = item.data(Qt.ItemDataRole.UserRole)
        if group_code:
            self.current_group_code = group_code
            
            # Update headers
            header_text = f"Group: {item.text()} (@{group_code})"
            self.chat_area_header.setText(header_text)
            self.member_list_label.setText(f"Members in {item.text()}")
            
            # Clear old chat and switch view
            self.chat_display.clear()
            self.terminal_display.clear()
            self.append_system_message(f"Joined group {item.text()}.")
            self.sidebar_stack.setCurrentWidget(self.member_panel)
            
            # Emit signal to fetch members
            self.group_selected.emit(group_code)

    def show_group_list_panel(self):
        """Switches the sidebar back to the group list."""
        self.sidebar_stack.setCurrentWidget(self.group_panel)
        self.chat_area_header.setText("Select a group to start chatting")
        self.member_list_widget.clear()
        self.chat_display.clear()
        self.terminal_display.clear()
        self.current_group_code = None

    def on_member_clicked(self, item: QListWidgetItem):
        self.current_target_username = item.data(Qt.ItemDataRole.UserRole)
        self.message_input.setPlaceholderText(f"Message to @{self.current_target_username}...")
        
        # If we click a user, check if we have their key
        if self.current_target_username != "Everyone":
            if self.current_target_username not in g_public_key_cache:
                self.append_system_message(f"Requesting public key for @{self.current_target_username}...")
                self.request_public_key.emit(self.current_target_username)

    def on_create_group(self):
        group_name = self.create_group_input.text()
        if group_name:
            self.create_group.emit(group_name)
            self.create_group_input.clear()

    def on_join_group(self):
        group_code = self.join_group_input.text()
        if group_code:
            self.join_group.emit(group_code.upper())
            self.join_group_input.clear()

    # --- Public Slots (called by MainWindow) ---
    def update_group_list(self, groups_list: list):
        self.group_list_widget.clear()
        if not groups_list:
            self.group_list_widget.addItem("No groups. Create or join one!")
        for group in groups_list:
            item = QListWidgetItem(group['group_name'])
            item.setData(Qt.ItemDataRole.UserRole, group['group_code'])
            self.group_list_widget.addItem(item)
            
    def update_member_list(self, members: list):
        self.member_list_widget.clear()
        
        # Add @Everyone target
        everyone_item = QListWidgetItem("@Everyone (Group Chat)")
        everyone_item.setData(Qt.ItemDataRole.UserRole, "Everyone")
        self.member_list_widget.addItem(everyone_item)

        # Add all other members
        for member in members:
            username = member.get("username")
            if username and username != self.my_username:
                item = QListWidgetItem(f"@{username}")
                item.setData(Qt.ItemDataRole.UserRole, username)
                self.member_list_widget.addItem(item)
        
        # Reselect the current target
        self.on_member_clicked(everyone_item)
        self.member_list_widget.setCurrentItem(everyone_item)
        
    def append_system_message(self, message: str):
        """Appends a centered system message to the chat."""
        html = f"""
        <div style='text-align: center; color: #8696A0; margin: 5px 0;'>
            <i>{message}</i>
        </div>
        """
        self.chat_display.append(html)

    def append_chat_message(self, sender: str, target: str, message: str):
        """Formats and appends a message to the CHAT display."""
        
        current_time = datetime.datetime.now().strftime("%H:%M")
        
        # --- Define sender color and initial ---
        sender_color = "#34B7F1" # Default blue for others
        sender_initial = sender[0].upper() if sender else "?"
        if sender != self.my_username:
            try:
                sender_hash = hash(sender)
                colors = ["#34B7F1", "#E542A3", "#F15C20", "#FFC400", "#00A884"]
                sender_color = colors[sender_hash % len(colors)]
            except:
                pass # Stick with default

        # --- Message for someone else that we can't read ---
        if sender != self.my_username and target != self.my_username and target != "Everyone":
            html = f"""
            <table style="width: 100%; margin-right: 30%; margin-bottom: 10px;">
                <tr>
                    <td style="width: 32px; vertical-align: top;">
                        <div style="width: 32px; height: 32px; border-radius: 16px; background-color: {sender_color}; color: white; text-align: center; line-height: 32px; font-weight: bold;">
                            {sender_initial}
                        </div>
                    </td>
                    <td style="padding-left: 8px;">
                        <div style="background-color: #202C33; display: inline-block; padding: 6px 10px; border-radius: 8px; text-align: left; max-width: 90%; opacity: 0.7;">
                            <b style="color: {sender_color};">{sender}</b> (to @{target})<br>
                            <div>
                                <span style="font-size: 11px; color: #8696A0; float: right; margin-left: 10px; margin-top: 4px;">{current_time}</span>
                                <span style="font-size: 15px; white-space: pre-wrap;"><i>[Encrypted DM] 🚫</i></span>
                            </div>
                        </div>
                    </td>
                </tr>
            </table>
            """
            self.chat_display.append(html)
            return

        # --- My own message ---
        if sender == self.my_username:
            target_text = f"(to @{target}) 🔒" if target != "Everyone" else ""
            html = f"""
            <div style='margin-left: 30%; text-align: right;'>
                <div style='background-color: #005C4B; display: inline-block; padding: 6px 10px; border-radius: 8px; text-align: left; margin-bottom: 10px;'>
                    <b style='color: #D9FDD3;'>Me</b> {target_text}<br>
                    <div>
                        <span style="font-size: 11px; color: #ADE2C8; float: right; margin-left: 10px; margin-top: 4px;">{current_time}</span>
                        <span style="font-size: 15px; white-space: pre-wrap;">{message}</span>
                    </div>
                </div>
            </div>
            """
        # --- Message from someone else (to me or Everyone) ---
        else:
            target_text = f"(to Me) 🔒" if target == self.my_username else ""
            html = f"""
            <table style="width: 100%; margin-right: 30%; margin-bottom: 10px;">
                <tr>
                    <td style="width: 32px; vertical-align: top;">
                        <div style="width: 32px; height: 32px; border-radius: 16px; background-color: {sender_color}; color: white; text-align: center; line-height: 32px; font-weight: bold;">
                            {sender_initial}
                        </div>
                    </td>
                    <td style="padding-left: 8px;">
                        <div style="background-color: #202C33; display: inline-block; padding: 6px 10px; border-radius: 8px; text-align: left; max-width: 90%;">
                            <b style="color: {sender_color};'>{sender}</b> {target_text}<br>
                            <div>
                                <span style="font-size: 11px; color: #8696A0; float: right; margin-left: 10px; margin-top: 4px;">{current_time}</span>
                                <span style="font-size: 15px; white-space: pre-wrap;">{message}</span>
                            </div>
                        </div>
                    </td>
                </tr>
            </table>
            """
        
        self.chat_display.append(html)

    def append_terminal_log(self, log_message: str):
        """Appends a raw log message to the TERMINAL display."""
        self.terminal_display.append(log_message)
        
    def show_group_action_error(self, error_msg: str):
        QMessageBox.warning(self, "Group Error", error_msg)

    def cache_public_key(self, username: str, public_key_pem: str):
        """Caches a public key and informs the user."""
        if public_key_pem:
            g_public_key_cache[username] = public_key_pem
            self.append_system_message(f"Received and cached key for @{username}. You can now send them DMs.")
        else:
            self.append_system_message(f"Could not find a public key for @{username}.")


# --- Main Window (Manages the Stack) ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Project-E Secure Chat Client")
        self.setGeometry(100, 100, 1000, 800) # Larger default size
        self.setWindowIcon(QIcon.fromTheme("security-high")) # Placeholder icon

        self.client_thread = WebSocketClientThread("ws://localhost:8765")

        # --- Create UI Pages ---
        self.login_page = LoginPage(self.client_thread)
        self.two_fa_page = TwoFAPage(self.client_thread)
        
        # MainAppWidget is initialized *after* login
        self.main_app_widget = None 

        # --- Create Stacked Widget ---
        self.stack = QStackedWidget()
        self.stack.addWidget(self.login_page)  # index 0
        self.stack.addWidget(self.two_fa_page)  # index 1
        # MainAppWidget will be added at index 2 later

        self.setCentralWidget(self.stack)

        # --- Connect Signals ---
        self.client_thread.connection_status.connect(self.login_page.global_status_label.setText)

        # Login/Signup signals
        self.client_thread.login_success.connect(self.on_login_success)
        self.client_thread.login_fail.connect(self.on_login_fail)
        self.client_thread.signup_fail.connect(self.on_signup_fail)
        
        # 2FA Signals
        self.client_thread.signup_success_needs_2fa.connect(self.on_signup_needs_2fa)
        self.client_thread.login_needs_2fa.connect(self.on_login_needs_2fa)
        self.client_thread.signup_complete.connect(self.on_signup_complete)

        # Start thread
        self.client_thread.start()

    def connect_main_app_signals(self):
        """Connects signals for the 2-column UI *after* it's created."""
        if not self.main_app_widget:
            return

        # Connect network signals TO the UI
        self.client_thread.message_received.connect(self.on_message_received)
        self.client_thread.crypto_log.connect(self.main_app_widget.append_terminal_log)
        self.client_thread.my_groups_list.connect(self.main_app_widget.update_group_list)
        self.client_thread.join_group_fail.connect(self.main_app_widget.show_group_action_error)
        self.client_thread.create_group_fail.connect(self.main_app_widget.show_group_action_error)
        self.client_thread.select_group_success.connect(lambda: print("Group selected")) # Logic is already in UI
        self.client_thread.group_member_list.connect(self.main_app_widget.update_member_list)
        self.client_thread.public_key_response.connect(self.main_app_widget.cache_public_key)
        self.client_thread.connection_status.connect(self.on_global_status_update)

        # Connect UI signals TO the network thread
        # --- THIS IS THE FIX ---
        self.main_app_widget.group_selected.connect(
            lambda group_code: self.client_thread.send_message({"type": "select_group", "group_code": group_code})
        )
        # --- END OF FIX ---
        self.main_app_widget.create_group.connect(
            lambda group_name: self.client_thread.send_message({"type": "create_group", "group_name": group_name})
        )
        self.main_app_widget.join_group.connect(
            lambda group_code: self.client_thread.send_message({"type": "join_group", "group_code": group_code})
        )
        self.main_app_widget.request_public_key.connect(
            lambda username: self.client_thread.send_message({"type": "get_public_key", "username": username})
        )
        
        # The main chat send logic
        self.main_app_widget.send_chat_message.connect(self.on_send_chat_message)

    def on_global_status_update(self, status: str):
        """Handles connection drops after login."""
        if "Connected" not in status:
            self.stack.setCurrentWidget(self.login_page)
            if self.main_app_widget:
                # Disconnect signals before deleting
                try:
                    self.client_thread.message_received.disconnect(self.on_message_received)
                    self.client_thread.crypto_log.disconnect(self.main_app_widget.append_terminal_log)
                    self.client_thread.my_groups_list.disconnect(self.main_app_widget.update_group_list)
                    # ... disconnect all other signals ...
                except TypeError:
                    pass # Signals might already be disconnected
                
                self.main_app_widget.deleteLater()
                self.main_app_widget = None
        # Update the login page's status label too
        self.login_page.global_status_label.setText(status)

    def on_login_success(self, username):
        # Create the main app widget *now*
        self.main_app_widget = MainAppWidget(my_username=username)
        self.stack.addWidget(self.main_app_widget) # Add at index 2
        
        # Connect all its signals
        self.connect_main_app_signals()
        
        self.stack.setCurrentWidget(self.main_app_widget)

    def on_login_fail(self, error_msg):
        if self.stack.currentWidget() == self.login_page:
            self.login_page.status_label.setText(error_msg)
        elif self.stack.currentWidget() == self.two_fa_page:
            self.two_fa_page.set_status(error_msg)
            self.stack.setCurrentWidget(self.login_page)
        QMessageBox.warning(self, "Login Failed", error_msg)

    def on_signup_fail(self, error_msg):
        if self.stack.currentWidget() == self.login_page:
            self.login_page.status_label.setText(error_msg)
        elif self.stack.currentWidget() == self.two_fa_page:
            self.two_fa_page.set_status(error_msg)
        QMessageBox.warning(self, "Signup Failed", error_msg)

    def on_signup_needs_2fa(self, provisioning_uri, secret):
        self.two_fa_page.set_mode("signup", provisioning_uri, secret)
        self.stack.setCurrentWidget(self.two_fa_page)

    def on_login_needs_2fa(self):
        self.two_fa_page.set_mode("login")
        self.stack.setCurrentWidget(self.two_fa_page)

    def on_signup_complete(self, message):
        QMessageBox.information(self, "Signup Complete", message)
        self.login_page.status_label.setText(message)
        self.stack.setCurrentWidget(self.login_page)
        
    def on_message_received(self, sender: str, target: str, message: str):
        """Wrapper to handle system messages separately."""
        if sender == "[SYSTEM]":
            self.main_app_widget.append_system_message(message)
        else:
            self.main_app_widget.append_chat_message(sender, target, message)
            
    def on_send_chat_message(self, target_username: str, text: str):
        """Encrypts and sends a chat message."""
        
        encrypted_content = None
        crypto_type = "UNKNOWN"

        try:
            if target_username == "Everyone":
                # --- Encrypt for Group ---
                if not self.client_thread.current_group_code:
                    self.main_app_widget.append_system_message("Error: No group code found.")
                    return
                key = security.derive_group_key(self.client_thread.current_group_code)
                encrypted_content = security.encrypt_with_group_key(key, text)
                crypto_type = "AES-GCM"
                # Display our own message
                self.main_app_widget.append_chat_message(self.client_thread.my_username, target_username, text)

            else:
                # --- Encrypt for DM ---
                public_key_pem = g_public_key_cache.get(target_username)
                if not public_key_pem:
                    # Key not in cache, request it again
                    self.main_app_widget.append_system_message(f"No key for @{target_username}. Requesting again...")
                    self.client_thread.send_message({"type": "get_public_key", "username": target_username})
                    return

                # Key is in cache, encrypt
                public_key = security.load_public_key(public_key_pem)
                encrypted_content = security.encrypt_with_public_key(public_key, text)
                crypto_type = "RSA-OAEP" # From security.py
                # Display our own DM
                self.main_app_widget.append_chat_message(self.client_thread.my_username, target_username, text)

            # --- Log to terminal ---
            self.main_app_widget.append_terminal_log(f"[SEND] Target: @{target_username}")
            self.main_app_widget.append_terminal_log(f"[PLAINTEXT] {text}")
            self.main_app_widget.append_terminal_log(f"[ENCRYPT:{crypto_type}] -> {encrypted_content[:30]}...")

            # Send the encrypted payload
            self.client_thread.send_message({
                "type": "chat",
                "target": target_username,
                "content": encrypted_content
            })

        except Exception as e:
            print(f"Encryption error: {e}")
            self.main_app_widget.append_terminal_log(f"[ENCRYPT:ERROR] {e}")


    def closeEvent(self, event):
        self.client_thread.stop()
        event.accept()

# --- Dark Mode Stylesheet ---
# Inspired by the WhatsApp dark mode reference
STYLESHEET = """
QWidget {
    background-color: #111B21; /* Very dark blue-gray */
    color: #E9EDEF; /* Off-white text */
    font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', sans-serif;
    font-size: 14px;
}

/* --- Login/2FA Pages --- */
#TitleLabel {
    font-size: 24px;
    font-weight: bold;
    color: #00A884; /* Bright green accent */
    margin-bottom: 20px;
}
#StatusLabel {
    color: #FF5555; /* Red for errors */
}
#GlobalStatusLabel {
    color: #8696A0; /* Gray for secondary text */
    font-size: 12px;
}

/* --- Main App Columns --- */
#Sidebar {
    background-color: #202C33; /* Dark gray */
    border-right: 1px solid #2f3b44;
}
#ChatArea {
    background-color: #0B141A; /* Darkest background for chat */
}

/* --- List Widgets (Groups & Members) --- */
QListWidget {
    border: none;
    background-color: transparent;
}
QListWidget::item {
    padding: 10px;
    border-bottom: 1px solid #1a242c;
}
QListWidget::item:selected, QListWidget::item:hover {
    background-color: #2A3942; /* Lighter gray for selection */
}
#SidebarHeader {
    font-size: 16px;
    font-weight: bold;
    padding: 10px 5px;
}

/* --- Chat & Terminal Area --- */
#ChatHeader {
    font-size: 16px;
    font-weight: bold;
    padding: 10px;
    background-color: #202C33;
}
#ChatDisplay {
    background-color: #0B141A; /* Darkest */
    border: none;
    color: #E9EDEF;
    font-size: 15px;
    padding: 10px;
}
#SecurityTerminal {
    background-color: #0D1B22; /* Slightly different dark */
    border: none;
    color: #00A884; /* Green text for terminal */
    padding: 5px;
}
QSplitter::handle {
    background-color: #202C33; /* Dark gray handle */
}
QSplitter::handle:vertical {
    height: 5px;
}

/* --- Input Fields & Buttons --- */
QLineEdit {
    background-color: #2A3942;
    border: 1px solid #374650;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 14px;
}
QLineEdit:focus {
    border: 1px solid #00A884;
}

QPushButton {
    background-color: #2A3942;
    color: #E9EDEF;
    border: none;
    border-radius: 8px;
    padding: 8px 16px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #374650;
}

#PrimaryButton {
    background-color: #00A884; /* Green accent */
    color: #111B21; /* Dark text on green */
}
#PrimaryButton:hover {
    background-color: #008769; /* Darker green */
}
"""


if __name__ == "__main__":
    try:
        load_or_generate_keys_sync()
    except Exception as e:
        QMessageBox.critical(None, "Key Error",
                             f"A fatal error occurred while loading/generating encryption keys: {e}\n\nThe application will now exit.")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET) # Apply the dark theme
    
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
