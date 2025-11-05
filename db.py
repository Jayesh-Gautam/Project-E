import sqlite3

DATABASE_FILE = "chat.db"


def init_db():
    """Initializes the database and creates tables if they don't exist."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()

        # --- MODIFIED for Phase 5: Added public_key column ---
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS users
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           username
                           TEXT
                           UNIQUE
                           NOT
                           NULL,
                           password_hash
                           TEXT
                           NOT
                           NULL,
                           totp_secret
                           TEXT,
                           is_totp_enabled
                           INTEGER
                           DEFAULT
                           0,
                           public_key
                           TEXT
                       );
                       """)
        # --- End of modifications ---

        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS groups
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           group_name
                           TEXT
                           NOT
                           NULL,
                           group_code
                           TEXT
                           UNIQUE
                           NOT
                           NULL
                       );
                       """)

        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS user_groups
                       (
                           user_id
                           INTEGER,
                           group_id
                           INTEGER,
                           PRIMARY
                           KEY
                       (
                           user_id,
                           group_id
                       ),
                           FOREIGN KEY
                       (
                           user_id
                       ) REFERENCES users
                       (
                           id
                       ),
                           FOREIGN KEY
                       (
                           group_id
                       ) REFERENCES groups
                       (
                           id
                       )
                           );
                       """)

        conn.commit()
    print("Database initialized.")


# --- MODIFIED for Phase 5: Now accepts public_key ---
def create_user(username, password_hash, totp_secret, public_key):
    """Adds a new user to the database with a TOTP secret and public key.
    Returns the new user's ID on success, None on failure.
    """
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, totp_secret, public_key) VALUES (?, ?, ?, ?)",
                (username, password_hash, totp_secret, public_key)
            )
            conn.commit()
            return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None
    except Exception as e:
        print(f"Database error in create_user: {e}")
        return None


# --- End of modifications ---

def get_user(username):
    """Retrieves a user's data by username."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            conn.row_factory = sqlite3.Row  # Allows accessing columns by name
            cursor = conn.cursor()
            # --- MODIFIED for Phase 5: Select public_key ---
            cursor.execute(
                "SELECT id, username, password_hash, totp_secret, is_totp_enabled, public_key FROM users WHERE username = ?",
                (username,)
            )
            user_row = cursor.fetchone()
            if user_row:
                return dict(user_row)
            return None
    except Exception as e:
        print(f"Database error in get_user: {e}")
        return None


def get_user_by_id(user_id):
    """Retrieves a user's data by user ID."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, totp_secret, is_totp_enabled, public_key FROM users WHERE id = ?",
                (user_id,)
            )
            user_row = cursor.fetchone()
            if user_row:
                return dict(user_row)
            return None
    except Exception as e:
        print(f"Database error in get_user_by_id: {e}")
        return None


def enable_totp_for_user(user_id):
    """Sets the is_totp_enabled flag to 1 for a user."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET is_totp_enabled = 1 WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            return True
    except Exception as e:
        print(f"Database error in enable_totp_for_user: {e}")
        return False


# --- NEW for Phase 5: Public Key and Group Member Functions ---

def get_public_key(username: str) -> str | None:
    """Retrieves a user's public key by username."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return result[0] if result else None
    except Exception as e:
        print(f"Database error in get_public_key: {e}")
        return None


def get_group_members(group_code: str) -> list:
    """Retrieves all users (id, username) in a specific group."""
    members = []
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                           SELECT u.id, u.username
                           FROM users u
                                    JOIN user_groups ug ON u.id = ug.user_id
                                    JOIN groups g ON ug.group_id = g.id
                           WHERE g.group_code = ?
                           """, (group_code,))
            rows = cursor.fetchall()
            for row in rows:
                members.append(dict(row))
            return members
    except Exception as e:
        print(f"Database error in get_group_members: {e}")
        return []


# --- Group Functions (unchanged) ---

def create_group(group_name, group_code, creator_user_id):
    """Creates a new group and adds the creator to it."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO groups (group_name, group_code) VALUES (?, ?)",
                (group_name, group_code)
            )
            new_group_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
                (creator_user_id, new_group_id)
            )
            conn.commit()
            return {"id": new_group_id, "group_name": group_name, "group_code": group_code}
    except sqlite3.IntegrityError:
        return None
    except Exception as e:
        print(f"Database error in create_group: {e}")
        return None


def join_group(user_id, group_code):
    """Adds a user to an existing group using the group code."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, group_name FROM groups WHERE group_code = ?", (group_code,))
            group = cursor.fetchone()

            if not group:
                return {"success": False, "error": "Group not found."}

            group_id, group_name = group

            try:
                cursor.execute(
                    "INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
                    (user_id, group_id)
                )
                conn.commit()
                return {"success": True, "group_name": group_name, "group_code": group_code}
            except sqlite3.IntegrityError:
                return {"success": False, "error": "Already a member."}

    except Exception as e:
        print(f"Database error in join_group: {e}")
        return {"success": False, "error": f"Server error: {e}"}


def get_user_groups(user_id):
    """Retrievess all groups a user is a member of."""
    groups = []
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                           SELECT g.group_name, g.group_code
                           FROM groups g
                                    JOIN user_groups ug ON g.id = ug.group_id
                           WHERE ug.user_id = ?
                           """, (user_id,))

            rows = cursor.fetchall()
            for row in rows:
                groups.append(dict(row))
            return groups
    except Exception as e:
        print(f"Database error in get_user_groups: {e}")
        return []


if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    print("Database file 'chat.db' is ready.")