import asyncio
import websockets
import json
import db  # Our database module
import security  # Our security module

# --- State Dictionaries ---

# {websocket: {"user_id": 1, "username": "alice", "current_group_code": "A4D8B1"}}
# MODIFIED Phase 5: No longer stores public_key, not needed in server memory.
LOGGED_IN_USERS = {}

# {websocket: user_id}
PENDING_2FA_VERIFICATION = {}

# {websocket: user_dict}
PENDING_LOGIN_2FA = {}


# --- Helper Functions ---

def get_user_from_websocket(websocket):
    return LOGGED_IN_USERS.get(websocket)


def get_user_id_from_websocket(websocket):
    user = get_user_from_websocket(websocket)
    return user.get("user_id") if user else None


def set_user_group(websocket, group_code):
    if websocket in LOGGED_IN_USERS:
        LOGGED_IN_USERS[websocket]["current_group_code"] = group_code
        print(f"User '{LOGGED_IN_USERS[websocket]['username']}' switched to group {group_code}")


# --- MODIFIED for Phase 5 ---
async def broadcast_message(sender_username, group_code, target_username, encrypted_content):
    """
    Broadcasts an encrypted message to all users in a group.
    The server cannot read 'encrypted_content'.
    """
    payload = {
        "type": "chat_message",
        "content": encrypted_content,  # This is the encrypted blob
        "sender_id": sender_username,
        "target": target_username  # "Everyone" or "specific_user"
    }
    json_payload = json.dumps(payload)

    tasks = []
    for ws, user_data in LOGGED_IN_USERS.items():
        if user_data.get("current_group_code") == group_code:
            tasks.append(ws.send(json_payload))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                print(f"Broadcast error: {result}")


# --- End of modifications ---

async def send_json_response(websocket, payload):
    try:
        await websocket.send(json.dumps(payload))
    except Exception as e:
        print(f"Error sending response: {e}")


# --- NEW for Phase 5: Broadcasts group member list ---
async def broadcast_group_members(group_code: str):
    """Fetches and broadcasts the member list for a group to all its members."""
    if not group_code:
        return

    members = db.get_group_members(group_code)
    payload = json.dumps({"type": "group_member_list", "members": members})

    tasks = []
    for ws, user_data in LOGGED_IN_USERS.items():
        if user_data.get("current_group_code") == group_code:
            tasks.append(ws.send(payload))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                print(f"Group member broadcast error: {result}")


# --- Handlers for different message types ---

async def handle_signup(websocket, data):
    username = data.get('username')
    password = data.get('password')
    public_key = data.get('public_key')  # NEW for Phase 5

    if not username or not password or not public_key:
        await send_json_response(websocket,
                                 {"type": "signup_fail", "error": "Username, password, and public key required."})
        return

    password_hash = security.hash_password(password)
    totp_secret = security.generate_totp_secret()

    # Create the user (but 2FA is not enabled yet)
    new_user_id = db.create_user(username, password_hash, totp_secret, public_key)

    if new_user_id:
        # User created, now they must verify 2FA
        provisioning_uri = security.get_provisioning_uri(totp_secret, username)
        PENDING_2FA_VERIFICATION[websocket] = new_user_id

        await send_json_response(websocket, {
            "type": "signup_success_needs_2fa",
            "provisioning_uri": provisioning_uri,
            "secret": totp_secret  # For "can't scan" fallback
        })
    else:
        await send_json_response(websocket, {"type": "signup_fail", "error": "Username already taken."})


async def handle_verify_totp_signup(websocket, data):
    """Handles the 2FA code sent after signup OR incomplete login."""
    user_id = PENDING_2FA_VERIFICATION.get(websocket)
    if not user_id:
        return

    user = db.get_user_by_id(user_id)
    if not user:
        return

    code = data.get("code")
    if security.verify_totp_code(user["totp_secret"], code):
        db.enable_totp_for_user(user_id)
        if websocket in PENDING_2FA_VERIFICATION:
            del PENDING_2FA_VERIFICATION[websocket]
        await send_json_response(websocket, {
            "type": "signup_complete",
            "message": "Signup complete! Please log in."
        })
    else:
        await send_json_response(websocket, {"type": "signup_fail", "error": "Invalid 2FA code. Try again."})


async def handle_login(websocket, data):
    username = data.get('username')
    password = data.get('password')

    if username in [u["username"] for u in LOGGED_IN_USERS.values()]:
        await send_json_response(websocket, {"type": "login_fail", "error": "User already logged in."})
        return

    user = db.get_user(username)

    if user and security.verify_password(password, user["password_hash"]):

        if user["is_totp_enabled"] == 0:
            print(f"User '{username}' logging in with incomplete 2FA. Re-triggering setup.")
            totp_secret = user["totp_secret"]
            provisioning_uri = security.get_provisioning_uri(totp_secret, username)
            PENDING_2FA_VERIFICATION[websocket] = user["id"]

            await send_json_response(websocket, {
                "type": "signup_success_needs_2fa",
                "provisioning_uri": provisioning_uri,
                "secret": totp_secret
            })
            return

        PENDING_LOGIN_2FA[websocket] = user
        await send_json_response(websocket, {"type": "login_needs_2fa"})
    else:
        await send_json_response(websocket, {"type": "login_fail", "error": "Invalid username or password."})


async def handle_verify_totp_login(websocket, data):
    """Handles the 2FA code sent after login."""
    user = PENDING_LOGIN_2FA.get(websocket)
    code = data.get("code")

    if not user:
        return

    if security.verify_totp_code(user["totp_secret"], code):
        if websocket in PENDING_LOGIN_2FA:
            del PENDING_LOGIN_2FA[websocket]

        LOGGED_IN_USERS[websocket] = {
            "user_id": user["id"],
            "username": user["username"],
            "current_group_code": None
        }

        await send_json_response(websocket, {"type": "login_success", "username": user["username"]})
        print(f"User '{user['username']}' logged in. Total users: {len(LOGGED_IN_USERS)}")

        await handle_get_my_groups(websocket)
    else:
        await send_json_response(websocket, {"type": "login_fail", "error": "Invalid 2FA code."})


async def handle_chat_message(websocket, data):
    """MODIFIED for Phase 5: Routes encrypted blobs."""
    sender_data = get_user_from_websocket(websocket)
    if not sender_data:
        await send_json_response(websocket, {"type": "error", "message": "Not logged in."})
        return

    group_code = sender_data.get("current_group_code")
    if not group_code:
        await send_json_response(websocket, {"type": "error", "message": "No group selected."})
        return

    encrypted_content = data.get("content")
    target_username = data.get("target")  # "Everyone" or "specific_user"

    if encrypted_content and target_username:
        sender_username = sender_data["username"]
        print(f"Routing E2E message in '{group_code}' from '{sender_username}' to '{target_username}'")
        await broadcast_message(sender_username, group_code, target_username, encrypted_content)


# --- Group Handlers ---

async def handle_get_my_groups(websocket):
    user_id = get_user_id_from_websocket(websocket)
    if not user_id: return
    groups = db.get_user_groups(user_id)
    await send_json_response(websocket, {"type": "my_groups_list", "groups": groups})


async def handle_create_group(websocket, data):
    user_id = get_user_id_from_websocket(websocket)
    if not user_id: return
    group_name = data.get("group_name")
    if not group_name:
        await send_json_response(websocket, {"type": "create_group_fail", "error": "Group name required."})
        return

    # Generate a unique group code
    while True:
        group_code = security.generate_group_code()
        if db.get_group_members(group_code) == []:  # Check if code is truly unique
            break

    new_group = db.create_group(group_name, group_code, user_id)
    if new_group:
        await send_json_response(websocket, {"type": "create_group_success", "group": new_group})
        await handle_get_my_groups(websocket)
    else:
        await send_json_response(websocket, {"type": "create_group_fail", "error": "Failed to create group."})


async def handle_join_group(websocket, data):
    user_id = get_user_id_from_websocket(websocket)
    if not user_id: return
    group_code = data.get("group_code")
    if not group_code:
        await send_json_response(websocket, {"type": "join_group_fail", "error": "Group code required."})
        return

    result = db.join_group(user_id, group_code.upper())
    if result["success"]:
        await send_json_response(websocket, {"type": "join_group_success", "group": result})
        await handle_get_my_groups(websocket)
        # Notify group of new member
        await broadcast_group_members(group_code.upper())
    else:
        await send_json_response(websocket, {"type": "join_group_fail", "error": result["error"]})


async def handle_select_group(websocket, data):
    user_id = get_user_id_from_websocket(websocket)
    group_code = data.get("group_code")
    if not user_id or not group_code: return

    set_user_group(websocket, group_code)
    await send_json_response(websocket, {"type": "select_group_success", "group_code": group_code})
    # Send the member list to the user who just joined
    await broadcast_group_members(group_code)


# --- NEW for Phase 5: Public Key Fetching ---
async def handle_get_public_key(websocket, data):
    target_username = data.get("username")
    if not target_username:
        return

    public_key = db.get_public_key(target_username)
    if public_key:
        await send_json_response(websocket, {
            "type": "public_key_response",
            "username": target_username,
            "public_key": public_key
        })
    else:
        await send_json_response(websocket, {
            "type": "error",
            "message": f"User '{target_username}' not found."
        })


# --- Main Connection Handler ---

async def chat_handler(websocket):
    print(f"Client connected: {websocket.remote_address}")
    current_group_code = None  # For disconnect broadcast

    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type")

                # Get user's current group before processing
                user = get_user_from_websocket(websocket)
                if user:
                    current_group_code = user.get("current_group_code")

                # --- Updated Message Routing ---
                if msg_type == "signup":
                    await handle_signup(websocket, data)
                elif msg_type == "verify_totp_signup":
                    await handle_verify_totp_signup(websocket, data)
                elif msg_type == "login":
                    await handle_login(websocket, data)
                elif msg_type == "verify_totp_login":
                    await handle_verify_totp_login(websocket, data)
                elif msg_type == "chat":
                    await handle_chat_message(websocket, data)
                elif msg_type == "create_group":
                    await handle_create_group(websocket, data)
                elif msg_type == "join_group":
                    await handle_join_group(websocket, data)
                elif msg_type == "select_group":
                    await handle_select_group(websocket, data)
                elif msg_type == "get_public_key":  # NEW
                    await handle_get_public_key(websocket, data)
                else:
                    await send_json_response(websocket,
                                             {"type": "error", "message": f"Unknown message type: {msg_type}"})

            except json.JSONDecodeError:
                await send_json_response(websocket, {"type": "error", "message": "Invalid JSON."})
            except Exception as e:
                print(f"Error processing message: {e}")
                await send_json_response(websocket, {"type": "error", "message": "Internal server error."})

    except websockets.exceptions.ConnectionClosedError:
        print(f"Client connection closed: {websocket.remote_address}")
    except Exception as e:
        print(f"An error occurred with {websocket.remote_address}: {e}")
    finally:
        # Cleanup all pending states
        if websocket in LOGGED_IN_USERS: del LOGGED_IN_USERS[websocket]
        if websocket in PENDING_2FA_VERIFICATION: del PENDING_2FA_VERIFICATION[websocket]
        if websocket in PENDING_LOGIN_2FA: del PENDING_LOGIN_2FA[websocket]

        # Notify group that user has left
        if current_group_code:
            print(f"User left group {current_group_code}, broadcasting member update.")
            await broadcast_group_members(current_group_code)

        print(f"Client {websocket.remote_address} disconnected. Cleaned up state.")


async def main():
    db.init_db()
    port = 8765
    print(f"Starting WebSocket server on ws://localhost:{port}")

    async with websockets.serve(chat_handler, "localhost", port):
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    asyncio.run(main())

