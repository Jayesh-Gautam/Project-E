import sys
import asyncio
import websockets
import json
import qrcode
import io
import os  # --- NEW for Phase 5

# Import our security module
import security  # --- NEW for Phase 5

# --- Pre-import check ---
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTextEdit, QLineEdit, QPushButton, QLabel, QStackedWidget,
        QFormLayout, QMessageBox, QListWidget, QListWidgetItem,
        QComboBox  # --- NEW for Phase 5
    )
    from PyQt6.QtCore import QThread, pyqtSignal, Qt
    from PyQt6.QtGui import QPixmap, QImage
except ImportError as e:
    print("--- FATAL ERROR ---")
    print(f"Could not import PyQt6. Error: {e}")
    print("Please make sure you are in your activated virtual environment (.venv)")
    print("and you have run: pip install -r requirements.txt")
    print("---------------------")
    sys.exit(1)
# --- End of check ---

from asyncqt import QEventLoop

# --- NEW for Phase 5: Key Management ---
PRIVATE_KEY_FILE = "client_private_key.pem"
# These globals will hold the *loaded key objects*
g_private_key = None
g_public_key = None
# This will hold the *PEM string* for sending to the server
g_public_key_pem = None
# This will cache public keys of other users
g_public_key_cache = {}  # { "username": "--- BEGIN PUBLIC KEY ---..." }


def load_or_generate_keys_sync():
    """
    Loads keys from disk if they exist, otherwise generates them.
    This is a synchronous function called once on startup.
    WARNING: Storing a private key in a plain file is NOT secure
    for a real application. It should be in a protected keystore.
    """
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
            os.remove(PRIVATE_KEY_FILE)  # Remove corrupted file
            load_or_generate_keys_sync()  # Recurse
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

    # In both cases, get the serializable PEM for the public key
    g_public_key_pem = security.serialize_public_key(g_public_key)


# --- End of Key Management ---


# This QThread is responsible for all asyncio and networking
class WebSocketClientThread(QThread):
    # Signals for login/signup
    login_success = pyqtSignal(str)
    login_fail = pyqtSignal(str)
    signup_success_needs_2fa = pyqtSignal(str, str)  # uri, secret
    login_needs_2fa = pyqtSignal()
    signup_complete = pyqtSignal(str)  # success message
    signup_fail = pyqtSignal(str)

    # Signals for chat
    message_received = pyqtSignal(str)
    connection_status = pyqtSignal(str)

    # Signals for groups
    my_groups_list = pyqtSignal(list)
    join_group_fail = pyqtSignal(str)
    create_group_fail = pyqtSignal(str)
    select_group_success = pyqtSignal(str)

    # --- NEW for Phase 5 ---
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
        self.current_group_code = None  # NEW: for symmetric encryption

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

                    # --- MODIFIED for Phase 5: Decryption ---
                    elif msg_type == "chat_message":
                        self.handle_encrypted_chat(data)

                    elif msg_type == "my_groups_list":
                        self.my_groups_list.emit(data.get("groups", []))
                    elif msg_type == "join_group_fail":
                        self.join_group_fail.emit(data.get("error", "Failed to join"))
                    elif msg_type == "create_group_fail":
                        self.create_group_fail.emit(data.get("error", "Failed to create"))
                    elif msg_type == "select_group_success":
                        self.current_group_code = data.get("group_code")  # Store for encryption
                        self.select_group_success.emit(self.current_group_code)

                    # --- Phase 4 Handlers ---
                    elif msg_type == "signup_success_needs_2fa":
                        self.signup_success_needs_2fa.emit(
                            data.get("provisioning_uri"),
                            data.get("secret")
                        )
                    elif msg_type == "login_needs_2fa":
                        self.login_needs_2fa.emit()
                    elif msg_type == "signup_complete":
                        self.signup_complete.emit(data.get("message"))

                    # --- NEW Phase 5 Handlers ---
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
                    self.message_received.emit(f"[RAW] {message}")

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            print(f"Consumer error: {e}")

    # --- THIS FUNCTION IS MODIFIED ---
    def handle_encrypted_chat(self, data: dict):
        """NEW: Decrypts an incoming chat message."""
        try:
            encrypted_content = data.get("content")
            sender_id = data.get("sender_id")
            target = data.get("target")

            # --- THIS IS THE FIX ---
            # We already displayed our own message when we sent it
            # (in ChatPage.on_send_clicked).
            # Ignore the echo from the server.
            if sender_id == self.my_username:
                return
                # --- END OF FIX ---

            decrypted_message = None

            if target == "Everyone":
                if not self.current_group_code: return
                key = security.derive_group_key(self.current_group_code)
                decrypted_message = security.decrypt_with_group_key(key, encrypted_content)

            elif target == self.my_username:
                # It's a DM for me
                decrypted_message = security.decrypt_with_private_key(g_private_key, encrypted_content)

            else:
                # It's a DM for someone else that we're seeing in the group.
                decrypted_message = f"[Encrypted DM for {target}]"

            if decrypted_message is None:
                return

                # At this point, sender_id is never "Me"
            formatted_msg = f"{sender_id} (to {target}): {decrypted_message}"

            # Refine display
            if target == "Everyone":
                formatted_msg = f"{sender_id}: {decrypted_message}"
            elif target == self.my_username:
                formatted_msg = f"{sender_id} (DM to Me): {decrypted_message}"
            # No other "else" needed, we already formatted the "DM for someone else" case

            self.message_received.emit(formatted_msg)

        except Exception as e:
            print(f"Error in handle_encrypted_chat: {e}")
            self.message_received.emit(f"[System] Failed to decrypt message from {sender_id}.")

    # --- END OF MODIFICATION ---

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


# --- Login/Signup Page ---
class LoginPage(QWidget):
    def __init__(self, client_thread):
        super().__init__()
        self.client_thread = client_thread
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        form_layout = QFormLayout()
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        form_layout.addRow("Username:", self.username_input)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Password:", self.password_input)
        layout.addLayout(form_layout)
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.on_login)
        layout.addWidget(self.login_button)
        self.signup_button = QPushButton("Sign Up")
        self.signup_button.clicked.connect(self.on_signup)
        layout.addWidget(self.signup_button)
        self.status_label = QLabel("Enter credentials")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

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
            # --- MODIFIED for Phase 5: Send public key ---
            self.client_thread.send_message({
                "type": "signup",
                "username": username,
                "password": password,
                "public_key": g_public_key_pem
            })


# --- 2FA Verification Page (Unchanged) ---
class TwoFAPage(QWidget):
    def __init__(self, client_thread):
        super().__init__()
        self.client_thread = client_thread
        self.mode = ""  # "signup" or "login"

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.title_label = QLabel("2-Factor Authentication")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = self.title_label.font()
        font.setBold(True)
        font.setPointSize(16)
        self.title_label.setFont(font)
        layout.addWidget(self.title_label)

        # --- QR Code Section (for signup) ---
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

        # --- Verification Code Input (for both) ---
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Enter 6-digit code")
        self.code_input.setMaxLength(6)
        self.code_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.code_input.returnPressed.connect(self.on_submit)
        layout.addWidget(self.code_input)

        self.submit_button = QPushButton("Verify")
        self.submit_button.clicked.connect(self.on_submit)
        layout.addWidget(self.submit_button)

        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

    def set_mode(self, mode, provisioning_uri=None, secret=None):
        """Sets the page for either 'signup' or 'login'."""
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
        """Converts a PIL Image to a QImage."""
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
            self.client_thread.send_message({
                "type": "verify_totp_signup",
                "code": code
            })
        elif self.mode == "login":
            self.status_label.setText("Verifying...")
            self.client_thread.send_message({
                "type": "verify_totp_login",
                "code": code
            })

    def set_status(self, message):
        """Called by MainWindow on a failure signal."""
        self.status_label.setText(message)


# --- Group Selection Page (Unchanged) ---
class GroupPage(QWidget):
    def __init__(self, client_thread):
        super().__init__()
        self.client_thread = client_thread
        self.groups_data = {}
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Your Groups (Double-click to join)"))
        self.group_list_widget = QListWidget()
        self.group_list_widget.itemDoubleClicked.connect(self.on_group_selected)
        layout.addWidget(self.group_list_widget)
        create_layout = QHBoxLayout()
        self.create_name_input = QLineEdit()
        self.create_name_input.setPlaceholderText("New group name")
        create_layout.addWidget(self.create_name_input)
        self.create_button = QPushButton("Create")
        self.create_button.clicked.connect(self.on_create_group)
        create_layout.addWidget(self.create_button)
        layout.addLayout(create_layout)
        join_layout = QHBoxLayout()
        self.join_code_input = QLineEdit()
        self.join_code_input.setPlaceholderText("Enter group code")
        join_layout.addWidget(self.join_code_input)
        self.join_button = QPushButton("Join")
        self.join_button.clicked.connect(self.on_join_group)
        join_layout.addWidget(self.join_button)
        layout.addLayout(join_layout)
        self.status_label = QLabel()
        layout.addWidget(self.status_label)

    def update_group_list(self, groups_list):
        self.group_list_widget.clear()
        self.groups_data.clear()
        if not groups_list:
            self.group_list_widget.addItem(QListWidgetItem("No groups. Create or join one!"))
        for group in groups_list:
            item_text = f"{group['group_name']} ({group['group_code']})"
            self.group_list_widget.addItem(QListWidgetItem(item_text))
            self.groups_data[item_text] = group['group_code']

    def on_group_selected(self, item):
        group_code = self.groups_data.get(item.text())
        if group_code:
            self.status_label.setText(f"Joining {item.text()}...")
            self.client_thread.send_message({"type": "select_group", "group_code": group_code})

    def on_create_group(self):
        group_name = self.create_name_input.text()
        if group_name:
            self.status_label.setText("Creating group...")
            self.client_thread.send_message({"type": "create_group", "group_name": group_name})
            self.create_name_input.clear()

    def on_join_group(self):
        group_code = self.join_code_input.text()
        if group_code:
            self.status_label.setText(f"Joining {group_code}...")
            self.client_thread.send_message({"type": "join_group", "group_code": group_code})
            self.join_code_input.clear()

    def on_action_fail(self, error_msg):
        self.status_label.setText(error_msg)
        QMessageBox.warning(self, "Group Error", error_msg)


# --- Chat Page (Unchanged from last version) ---
class ChatPage(QWidget):
    def __init__(self, client_thread):
        super().__init__()
        self.client_thread = client_thread
        self.current_group_code = None  # NEW

        self.layout = QVBoxLayout(self)
        self.current_group_label = QLabel("No group selected")
        self.current_group_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.current_group_label)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.layout.addWidget(self.chat_display)

        # --- NEW: Target Selector Dropdown ---
        self.target_selector = QComboBox()
        self.target_selector.addItem("Everyone (Group)", "Everyone")
        self.layout.addWidget(self.target_selector)
        # --- End of new ---

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        self.message_input.returnPressed.connect(self.on_send_clicked)
        self.layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.on_send_clicked)
        self.layout.addWidget(self.send_button)

    def on_send_clicked(self):
        text = self.message_input.text()
        if not text:
            return

        target_username = self.target_selector.currentData()
        if not target_username:
            target_username = "Everyone"  # Fallback

        encrypted_content = None

        try:
            if target_username == "Everyone":
                # --- Encrypt for Group ---
                if not self.current_group_code:
                    self.append_message("[SYSTEM] Error: No group code found.")
                    return
                key = security.derive_group_key(self.current_group_code)
                encrypted_content = security.encrypt_with_group_key(key, text)
                # Display our own message
                self.append_message(f"Me: {text}")

            else:
                # --- Encrypt for DM ---
                public_key_pem = g_public_key_cache.get(target_username)
                if not public_key_pem:
                    # Key not in cache, request it
                    self.append_message(f"[SYSTEM] Fetching key for {target_username}... Try sending again.")
                    self.client_thread.send_message({"type": "get_public_key", "username": target_username})
                    return

                # Key is in cache, encrypt
                public_key = security.load_public_key(public_key_pem)
                encrypted_content = security.encrypt_with_public_key(public_key, text)
                # Display our own DM
                self.append_message(f"Me (to {target_username}): {text}")

            # Send the encrypted payload
            self.client_thread.send_message({
                "type": "chat",
                "target": target_username,
                "content": encrypted_content
            })

            self.message_input.clear()

        except Exception as e:
            print(f"Encryption error: {e}")
            self.append_message(f"[SYSTEM] Failed to encrypt message: {e}")

    def append_message(self, message):
        self.chat_display.append(message)

    def set_current_group(self, group_code):
        self.current_group_code = group_code  # Store for encryption
        self.current_group_label.setText(f"Chatting in group: {group_code}")
        self.chat_display.clear()
        self.chat_display.append(f"[SYSTEM] Joined group {group_code}. Messages are end-to-end encrypted.")

    def update_member_list(self, members: list):
        """NEW: Updates the target dropdown with group members."""
        self.target_selector.clear()
        self.target_selector.addItem("Everyone (Group)", "Everyone")

        my_username = self.client_thread.my_username
        for member in members:
            username = member.get("username")
            if username and username != my_username:
                self.target_selector.addItem(username, username)  # Text and Data are the same


# --- Main Window (Holds the Stack) ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat Client (Phase 5)")
        self.setGeometry(100, 100, 400, 500)

        self.client_thread = WebSocketClientThread("ws://localhost:8765")

        # --- Create UI Pages ---
        self.login_page = LoginPage(self.client_thread)
        self.two_fa_page = TwoFAPage(self.client_thread)
        self.group_page = GroupPage(self.client_thread)
        self.chat_page = ChatPage(self.client_thread)

        # --- Create Stacked Widget ---
        self.stack = QStackedWidget()
        self.stack.addWidget(self.login_page)  # index 0
        self.stack.addWidget(self.two_fa_page)  # index 1
        self.stack.addWidget(self.group_page)  # index 2
        self.stack.addWidget(self.chat_page)  # index 3

        # --- Main Window Layout ---
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        self.global_status_label = QLabel("Welcome! Loading keys...")
        self.global_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.global_status_label)
        main_layout.addWidget(self.stack)
        self.setCentralWidget(main_widget)

        # --- Connect Signals ---
        self.client_thread.connection_status.connect(self.on_global_status)
        self.client_thread.message_received.connect(self.on_message_received)

        # Login/Signup signals
        self.client_thread.login_success.connect(self.on_login_success)
        self.client_thread.login_fail.connect(self.on_login_fail)
        self.client_thread.signup_fail.connect(self.on_signup_fail)

        # Group signals
        self.client_thread.my_groups_list.connect(self.group_page.update_group_list)
        self.client_thread.join_group_fail.connect(self.group_page.on_action_fail)
        self.client_thread.create_group_fail.connect(self.group_page.on_action_fail)
        self.client_thread.select_group_success.connect(self.on_select_group_success)

        # 2FA Signals
        self.client_thread.signup_success_needs_2fa.connect(self.on_signup_needs_2fa)
        self.client_thread.login_needs_2fa.connect(self.on_login_needs_2fa)
        self.client_thread.signup_complete.connect(self.on_signup_complete)

        # --- NEW Phase 5 Signals ---
        self.client_thread.group_member_list.connect(self.chat_page.update_member_list)
        self.client_thread.public_key_response.connect(self.on_public_key_response)

        self.client_thread.start()

    def on_global_status(self, status):
        self.global_status_label.setText(status)
        if "Connected" not in status:
            self.stack.setCurrentWidget(self.login_page)

    def on_login_success(self, username):
        self.global_status_label.setText(f"Logged in as {username}")
        self.stack.setCurrentWidget(self.group_page)

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

    def on_select_group_success(self, group_code):
        self.global_status_label.setText(f"Group: {group_code}")
        self.chat_page.set_current_group(group_code)
        self.stack.setCurrentWidget(self.chat_page)

    # --- THIS FUNCTION IS MODIFIED ---
    def on_message_received(self, formatted_message):
        """
        Receives formatted messages from the network thread
        (which has already handled decryption and filtering).
        """
        # --- THIS IS THE FIX ---
        # The old filtering logic for DM echos is no longer needed,
        # as handle_encrypted_chat now filters ALL self-messages.
        self.chat_page.append_message(formatted_message)
        # --- END OF FIX ---

    # --- 2FA Slots ---

    def on_signup_needs_2fa(self, provisioning_uri, secret):
        self.global_status_label.setText("Complete 2FA Setup")
        self.two_fa_page.set_mode("signup", provisioning_uri, secret)
        self.stack.setCurrentWidget(self.two_fa_page)

    def on_login_needs_2fa(self):
        self.global_status_label.setText("Verify 2FA")
        self.two_fa_page.set_mode("login")
        self.stack.setCurrentWidget(self.two_fa_page)

    def on_signup_complete(self, message):
        QMessageBox.information(self, "Signup Complete", message)
        self.login_page.status_label.setText(message)
        self.stack.setCurrentWidget(self.login_page)

    # --- NEW Phase 5 Slots ---

    def on_public_key_response(self, username, public_key_pem):
        """Cache another user's public key when received."""
        if public_key_pem:
            g_public_key_cache[username] = public_key_pem
            self.chat_page.append_message(f"[SYSTEM] Received key for {username}. You can now send them a DM.")
        else:
            self.chat_page.append_message(f"[SYSTEM] Could not find a key for {username}.")

    def closeEvent(self, event):
        self.client_thread.stop()
        event.accept()


if __name__ == "__main__":
    # --- NEW: Load keys *before* starting the app ---
    try:
        load_or_generate_keys_sync()
    except Exception as e:
        QMessageBox.critical(None, "Key Error",
                             f"A fatal error occurred while loading/generating encryption keys: {e}\n\nThe application will now exit.")
        sys.exit(1)

    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

