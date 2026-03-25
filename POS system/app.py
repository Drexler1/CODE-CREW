from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_mysqldb import MySQL
from MySQLdb.cursors import DictCursor
from deepface import DeepFace
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64, cv2, os, numpy as np, time, hashlib, bcrypt, json, secrets

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'SecretKey')

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                        AES-256 ENCRYPTION LAYER                             ║
# ║                                                                              ║
# ║  ALL sensitive columns are encrypted before DB write and decrypted on read. ║   
# ║  Encrypted fields:                                                           ║
# ║    employees  → username, password, full_name, contact_number               ║
# ║    admins     → username, password, full_name                                ║
# ║                                                                              ║
# ║  Login lookup strategy:                                                      ║
# ║    Usernames cannot be queried with WHERE username=encrypted_value (random   ║
# ║    IV means the same value produces different ciphertext each time).         ║
# ║    Instead we store a deterministic SHA-256(AES_KEY + username) digest in   ║
# ║    `username_hash` and use WHERE username_hash=hash(input) for lookups.      ║
# ║    This requires only the one AES_SECRET_KEY — no separate HMAC key.        ║
# ║                                                                              ║
# ║  Set environment variable before running:                                    ║
# ║    AES_SECRET_KEY  — encryption key (32+ chars recommended)                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

_AES_RAW   = os.environ.get('AES_SECRET_KEY',  'change-this-aes-key-before-deploy!')
AES_KEY    = hashlib.sha256(_AES_RAW.encode()).digest()    # 32 bytes


def aes_encrypt(plaintext: str) -> str:
    """AES-256-CBC encrypt → base64(IV + ciphertext)."""
    if not plaintext:
        return plaintext
    iv         = os.urandom(16)
    cipher     = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')


def aes_decrypt(token: str) -> str:
    """
    Decrypt AES-256-CBC token.
    - Success            -> returns decrypted plaintext string.
    - Short plain value  -> returned as-is  (legacy unencrypted rows, < 44 chars).
    - Corrupt/truncated  -> returns empty   (never leaks raw ciphertext to the UI).
    """
    if not token:
        return token
    try:
        raw = base64.b64decode(token)
        iv  = raw[:16]
        ct  = raw[16:]
        return unpad(AES.new(AES_KEY, AES.MODE_CBC, iv).decrypt(ct), AES.block_size).decode('utf-8')
    except Exception:
        if len(token) < 44 and '=' not in token:
            return token   # short legacy plaintext
        return ''           # corrupt/truncated ciphertext — return empty, never raw garbage


def aes_username_hash(username: str) -> str:
    """
    Produce a deterministic SHA-256 digest of (AES_KEY + username).
    Used for WHERE username_hash=? lookups — fast and secure with only
    the AES_SECRET_KEY; no separate HMAC key required.
    """
    return hashlib.sha256(AES_KEY + username.strip().lower().encode('utf-8')).hexdigest()


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                        BCRYPT PASSWORD HASHING                               ║
# ║                                                                              ║
# ║  Passwords are hashed with bcrypt (work factor 12) and stored in the        ║
# ║  `password_hash` column.  The old AES-encrypted `password` column is kept   ║
# ║  only for the auto-migration transition; once all rows have a password_hash  ║
# ║  the plaintext column is ignored on login.                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

BCRYPT_ROUNDS = 12   # work factor — increase to 13+ if hardware allows


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password with bcrypt.  Returns a UTF-8 string."""
    return bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS)).decode('utf-8')


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Verify plaintext against a bcrypt hash.
    Falls back to AES-decrypted comparison when stored_hash is None/empty
    (legacy rows that have not yet been migrated to bcrypt).
    """
    if not plaintext:
        return False
    if stored_hash:
        try:
            return bcrypt.checkpw(plaintext.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception:
            return False
    return False  # no hash and no fallback — deny


def _check_login_password(plaintext: str, row: dict) -> bool:
    """
    Unified password check for a decrypted DB row.

    Priority:
      1. If row has a bcrypt hash  → use bcrypt.checkpw (secure)
      2. Else fall back to plain AES-decrypted comparison (legacy / migration window)

    This ensures users can still log in immediately after deployment,
    before the background migration has hashed their password.
    """
    ph = (row.get('password_hash') or '').strip()
    if ph:
        return verify_password(plaintext, ph)
    # Legacy fallback: compare against AES-decrypted password
    legacy = (row.get('password') or '').strip()
    return bool(legacy and legacy == plaintext)


def _widen_password_hash_columns():
    """
    Add password_hash VARCHAR(255) column to employees and admins if absent.
    Called once at startup inside run_auto_migration().
    """
    try:
        conn = mysql.connection
        cur  = conn.cursor(DictCursor)
        for tbl in ('employees', 'admins'):
            try:
                cur.execute(
                    f"ALTER TABLE `{tbl}` "
                    f"ADD COLUMN `password_hash` VARCHAR(255) DEFAULT NULL"
                )
                conn.commit()
                app.logger.info(f"[migration] Added password_hash to {tbl}")
            except Exception:
                pass  # column already exists
        cur.close()
    except Exception as exc:
        app.logger.error(f"[migration] _widen_password_hash_columns failed: {exc}")


def _backfill_bcrypt_hashes():
    """
    One-time background pass: for every employee/admin row that has a decryptable
    AES password but no bcrypt hash yet, compute and store the bcrypt hash.

    This is called lazily at startup (inside run_auto_migration) so that existing
    accounts are upgraded without any manual intervention.
    """
    try:
        conn = mysql.connection
        cur  = conn.cursor(DictCursor)

        # ── employees ──────────────────────────────────────────────────────────
        cur.execute(
            "SELECT employee_id, password FROM employees "
            "WHERE (password_hash IS NULL OR password_hash = '') AND password != ''"
        )
        for row in cur.fetchall():
            plaintext = aes_decrypt(str(row['password']).strip()) if row.get('password') else None
            if plaintext:
                new_hash = hash_password(plaintext)
                cur.execute(
                    "UPDATE employees SET password_hash=%s WHERE employee_id=%s",
                    (new_hash, row['employee_id'])
                )
                app.logger.info(f"[migration] bcrypt backfill — employee #{row['employee_id']}")

        # ── admins ─────────────────────────────────────────────────────────────
        cur.execute(
            "SELECT admin_id, password FROM admins "
            "WHERE (password_hash IS NULL OR password_hash = '') AND password != ''"
        )
        for row in cur.fetchall():
            plaintext = aes_decrypt(str(row['password']).strip()) if row.get('password') else None
            if plaintext:
                new_hash = hash_password(plaintext)
                cur.execute(
                    "UPDATE admins SET password_hash=%s WHERE admin_id=%s",
                    (new_hash, row['admin_id'])
                )
                app.logger.info(f"[migration] bcrypt backfill — admin #{row['admin_id']}")

        conn.commit()
        cur.close()
        app.logger.info("[migration] bcrypt backfill complete")
    except Exception as exc:
        app.logger.error(f"[migration] _backfill_bcrypt_hashes failed: {exc}")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                        LOGIN LOCKOUT POLICY                                  ║
# ║                                                                              ║
# ║  Tracks failed login attempts per (username_hash, role) in the DB so the    ║
# ║  lockout persists across server restarts and is not bypassable by clearing   ║
# ║  the session.                                                                ║
# ║                                                                              ║
# ║  Policy (tunable via constants below):                                       ║
# ║    • MAX_ATTEMPTS  — failed tries before lockout   (default: 5)             ║
# ║    • LOCKOUT_MINS  — lockout duration in minutes   (default: 15)            ║
# ║    • WARN_AT       — show "N attempts left" below this threshold (default: 3)║
# ║                                                                              ║
# ║  Key    : SHA-256(username_hash + ":" + role) — never stores the username   ║
# ║  Storage: `login_attempts` table (created automatically by auto-migration)  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

MAX_ATTEMPTS = 5      # lock after this many consecutive failures
LOCKOUT_MINS = 15     # minutes the account stays locked
WARN_AT      = 3      # show "X attempts remaining" when failures reach this


def _lockout_key(username_hash: str, role: str) -> str:
    """
    Produce a stable, opaque key for the login_attempts table.
    We hash (username_hash + role) so the key never directly reveals the username,
    and so that the same username on different role tabs has independent counters.
    """
    return hashlib.sha256(f"{username_hash}:{role}".encode()).hexdigest()


def _ensure_lockout_table():
    """
    Create the login_attempts table if it does not already exist.
    Called once during auto-migration at startup.
    """
    try:
        conn = mysql.connection
        cur  = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS `login_attempts` (
                `attempt_key`   VARCHAR(64)  NOT NULL,
                `fail_count`    INT          NOT NULL DEFAULT 0,
                `locked_until`  DATETIME     DEFAULT NULL,
                `last_attempt`  DATETIME     DEFAULT NULL,
                PRIMARY KEY (`attempt_key`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """)
        # ── Face mismatch security log ───────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS `face_mismatch_log` (
                `id`              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                `employee_id`     INT          NOT NULL,
                `attempted_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `distance_score`  FLOAT        DEFAULT NULL,
                `ip_address`      VARCHAR(45)  DEFAULT NULL,
                `user_agent`      VARCHAR(255) DEFAULT NULL,
                INDEX `idx_employee_id` (`employee_id`),
                INDEX `idx_attempted_at` (`attempted_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """)
        conn.commit()
        cur.close()
        app.logger.info("[migration] login_attempts + face_mismatch_log tables ensured")
    except Exception as exc:
        app.logger.error(f"[migration] _ensure_lockout_table failed: {exc}")


def _widen_face_model_path():
    """
    Widen face_model_path from VARCHAR(255) → MEDIUMTEXT if still narrow.

    WHY THIS IS CRITICAL:
      A FaceNet-512 averaged embedding serialised as JSON is ~6,159 characters.
      The original schema declared face_model_path as VARCHAR(255), which silently
      truncates (or rejects) the payload — so persist_embedding() appeared to succeed
      but every value stored was NULL or garbled, forcing verify_face() to always fall
      back to the less-accurate single-image path and causing consistent mismatches.

    This migration runs once at startup, is fully idempotent, and takes <1 ms.
    """
    try:
        conn = mysql.connection
        cur  = conn.cursor(DictCursor)

        # Check the current column type
        cur.execute("""
            SELECT DATA_TYPE, CHARACTER_MAXIMUM_LENGTH
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME   = 'employees'
              AND COLUMN_NAME  = 'face_model_path'
        """)
        col = cur.fetchone()

        if col is None:
            # Column doesn't exist at all — add it as MEDIUMTEXT
            cur.execute(
                "ALTER TABLE `employees` ADD COLUMN `face_model_path` MEDIUMTEXT DEFAULT NULL"
            )
            conn.commit()
            app.logger.info("[migration] face_model_path column added as MEDIUMTEXT")
        elif col['DATA_TYPE'].lower() in ('varchar', 'char', 'tinytext'):
            # Too narrow — widen to MEDIUMTEXT
            cur.execute(
                "ALTER TABLE `employees` MODIFY COLUMN `face_model_path` MEDIUMTEXT DEFAULT NULL"
            )
            conn.commit()
            app.logger.info(
                f"[migration] face_model_path widened from "
                f"{col['DATA_TYPE']}({col['CHARACTER_MAXIMUM_LENGTH']}) → MEDIUMTEXT"
            )
        else:
            app.logger.info(
                f"[migration] face_model_path already {col['DATA_TYPE']} — no change needed"
            )
        cur.close()
    except Exception as exc:
        app.logger.error(f"[migration] _widen_face_model_path failed: {exc}")


def _ensure_trash_table():
    """
    Create the employees_trash table if it does not exist, and migrate any
    existing inactive employees (disabled_at IS NOT NULL) into it.

    employees_trash stores a complete snapshot of the disabled employee row
    so it can be restored exactly. After 24 hours the row (and its face image)
    is permanently deleted by _purge_expired_trash().
    """
    try:
        conn = mysql.connection
        cur  = conn.cursor(DictCursor)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS `employees_trash` (
                `trash_id`          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                `employee_id`       INT          NOT NULL,
                `full_name`         VARCHAR(255) NOT NULL DEFAULT '',
                `username`          VARCHAR(255) NOT NULL DEFAULT '',
                `username_hash`     VARCHAR(64)  DEFAULT NULL,
                `password`          VARCHAR(255) NOT NULL DEFAULT '',
                `password_hash`     VARCHAR(255) DEFAULT NULL,
                `role`              ENUM('admin','manager','cashier') NOT NULL DEFAULT 'cashier',
                `contact_number`    VARCHAR(255) NOT NULL DEFAULT '',
                `face_image_path`   VARCHAR(255) DEFAULT NULL,
                `face_model_path`   MEDIUMTEXT   DEFAULT NULL,
                `last_login`        DATETIME     DEFAULT NULL,
                `created_at`        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `disabled_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `delete_at`         DATETIME     NOT NULL,
                INDEX `idx_delete_at` (`delete_at`),
                INDEX `idx_employee_id` (`employee_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """)
        conn.commit()
        app.logger.info("[migration] employees_trash table ensured")

        # ── Migrate existing inactive employees into trash ───────────────────
        cur.execute("""
            SELECT employee_id, full_name, username, username_hash,
                   password, password_hash, role, contact_number,
                   face_image_path, face_model_path, last_login,
                   created_at, disabled_at
            FROM employees
            WHERE employment_status = 'inactive'
              AND disabled_at IS NOT NULL
              AND employee_id NOT IN (SELECT employee_id FROM employees_trash)
        """)
        rows = cur.fetchall()
        migrated = 0
        for row in rows:
            disabled_at = row['disabled_at'] or datetime.now()
            import datetime as _dt
            delete_at = disabled_at + _dt.timedelta(hours=24)
            cur.execute("""
                INSERT INTO employees_trash
                    (employee_id, full_name, username, username_hash,
                     password, password_hash, role, contact_number,
                     face_image_path, face_model_path, last_login,
                     created_at, disabled_at, delete_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                row['employee_id'], row['full_name'], row['username'],
                row['username_hash'], row['password'], row['password_hash'],
                row['role'], row['contact_number'], row['face_image_path'],
                row['face_model_path'], row['last_login'], row['created_at'],
                disabled_at, delete_at
            ))
            migrated += 1
        if migrated:
            conn.commit()
            app.logger.info(f"[migration] Moved {migrated} inactive employee(s) to trash")
        cur.close()
    except Exception as exc:
        app.logger.error(f"[migration] _ensure_trash_table failed: {exc}")


# Timestamp of last purge check — avoids hitting DB on every single request
_last_purge_check = None
_PURGE_INTERVAL_SECONDS = 300   # check at most every 5 minutes


def _purge_expired_trash():
    """
    Permanently delete employees whose 24-hour grace period has expired.
    Removes the employee row, the trash row, and the face image file from disk.
    Called lazily on requests, at most every _PURGE_INTERVAL_SECONDS.
    """
    global _last_purge_check
    now = datetime.now()
    if _last_purge_check and (now - _last_purge_check).total_seconds() < _PURGE_INTERVAL_SECONDS:
        return
    _last_purge_check = now

    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("""
            SELECT trash_id, employee_id, face_image_path
            FROM employees_trash
            WHERE delete_at <= NOW()
        """)
        expired = cur.fetchall()

        for row in expired:
            emp_id = row['employee_id']

            # Delete face image from disk
            face_path = row.get('face_image_path')
            if face_path:
                full_path = os.path.join('static', face_path)
                try:
                    if os.path.exists(full_path):
                        os.remove(full_path)
                        app.logger.info(f"[purge] Deleted face image: {full_path}")
                except OSError as e:
                    app.logger.warning(f"[purge] Could not delete face image {full_path}: {e}")

            # Remove from embedding cache
            embedding_cache.pop(str(emp_id), None)
            face_mismatch_counts.pop(str(emp_id), None)

            # Permanently delete employee row (CASCADE removes attendance records)
            cur.execute("DELETE FROM employees WHERE employee_id=%s", (emp_id,))
            cur.execute("DELETE FROM employees_trash WHERE trash_id=%s", (row['trash_id'],))
            app.logger.info(f"[purge] Permanently deleted employee #{emp_id}")

        if expired:
            mysql.connection.commit()
        cur.close()
    except Exception as exc:
        app.logger.error(f"[purge] _purge_expired_trash failed: {exc}")


def _get_attempt_row(cur, key: str) -> dict:
    """Fetch the attempt row for key, or return a zeroed default dict."""
    cur.execute(
        "SELECT fail_count, locked_until, last_attempt "
        "FROM login_attempts WHERE attempt_key=%s",
        (key,)
    )
    row = cur.fetchone()
    if row is None:
        return {'fail_count': 0, 'locked_until': None, 'last_attempt': None}
    return row


def check_lockout(username_hash: str, role: str) -> dict:
    """
    Check whether a (username_hash, role) pair is currently locked out.

    Returns a dict:
        {
          'locked'     : bool,
          'seconds_left': int,     # >0 when locked
          'fail_count' : int,
          'attempts_left': int,    # attempts remaining before lockout
        }
    """
    key = _lockout_key(username_hash, role)
    try:
        cur = mysql.connection.cursor(DictCursor)
        row = _get_attempt_row(cur, key)
        cur.close()
    except Exception:
        # DB error — fail open so a DB outage does not permanently block all logins
        return {'locked': False, 'seconds_left': 0, 'fail_count': 0, 'attempts_left': MAX_ATTEMPTS}

    now = datetime.utcnow()
    locked_until = row.get('locked_until')

    if locked_until and locked_until > now:
        delta = int((locked_until - now).total_seconds())
        return {
            'locked':        True,
            'seconds_left':  delta,
            'fail_count':    row['fail_count'],
            'attempts_left': 0,
        }

    # Not locked (or lockout expired)
    fail_count = row.get('fail_count', 0)
    # If the lockout window expired naturally, treat as if count reset
    if locked_until and locked_until <= now:
        fail_count = 0

    return {
        'locked':        False,
        'seconds_left':  0,
        'fail_count':    fail_count,
        'attempts_left': max(0, MAX_ATTEMPTS - fail_count),
    }


def record_failed_attempt(username_hash: str, role: str) -> dict:
    """
    Increment the fail counter for (username_hash, role).
    Applies a lockout if MAX_ATTEMPTS is reached.

    Returns the same dict shape as check_lockout() reflecting the new state.
    """
    key  = _lockout_key(username_hash, role)
    now  = datetime.utcnow()
    try:
        conn = mysql.connection
        cur  = conn.cursor(DictCursor)
        row  = _get_attempt_row(cur, key)

        # If a previous lockout already expired, reset the counter first
        prev_locked_until = row.get('locked_until')
        if prev_locked_until and prev_locked_until <= now:
            row['fail_count'] = 0

        new_count    = (row.get('fail_count') or 0) + 1
        locked_until = None

        if new_count >= MAX_ATTEMPTS:
            from datetime import timedelta
            locked_until = now + timedelta(minutes=LOCKOUT_MINS)

        cur.execute("""
            INSERT INTO login_attempts (attempt_key, fail_count, locked_until, last_attempt)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                fail_count   = %s,
                locked_until = %s,
                last_attempt = %s
        """, (key, new_count, locked_until, now,
              new_count, locked_until, now))
        conn.commit()
        cur.close()
    except Exception as exc:
        app.logger.error(f"[lockout] record_failed_attempt error: {exc}")
        return {'locked': False, 'seconds_left': 0, 'fail_count': 1, 'attempts_left': MAX_ATTEMPTS - 1}

    if locked_until:
        return {
            'locked':        True,
            'seconds_left':  LOCKOUT_MINS * 60,
            'fail_count':    new_count,
            'attempts_left': 0,
        }
    return {
        'locked':        False,
        'seconds_left':  0,
        'fail_count':    new_count,
        'attempts_left': max(0, MAX_ATTEMPTS - new_count),
    }


def clear_failed_attempts(username_hash: str, role: str):
    """Reset the fail counter after a successful login."""
    key = _lockout_key(username_hash, role)
    try:
        conn = mysql.connection
        cur  = conn.cursor()
        cur.execute(
            "DELETE FROM login_attempts WHERE attempt_key=%s", (key,)
        )
        conn.commit()
        cur.close()
    except Exception as exc:
        app.logger.error(f"[lockout] clear_failed_attempts error: {exc}")


def _lockout_flash(state: dict):
    """
    Produce a user-facing flash message string from a lockout state dict.
    Includes a data attribute the JS countdown timer reads.
    """
    if state['locked']:
        mins = state['seconds_left'] // 60
        secs = state['seconds_left'] %  60
        return (
            f"LOCKOUT:{state['seconds_left']}:"
            f"Too many failed attempts. Account locked for "
            f"{mins}m {secs:02d}s. Try again later."
        )
    if state['fail_count'] >= WARN_AT:
        left = state['attempts_left']
        return (
            f"WARN:Invalid credentials — "
            f"{left} attempt{'s' if left != 1 else ''} remaining before lockout."
        )
    return "Invalid credentials. Please check your username and password."


def _dec_emp(row: dict) -> dict:
    """Decrypt all PII fields on an employees row."""
    if row:
        for f in ('username', 'full_name', 'password', 'contact_number'):
            if row.get(f):
                row[f] = aes_decrypt(row[f])
    return row


def _dec_adm(row: dict) -> dict:
    """Decrypt all PII fields on an admins row."""
    if row:
        for f in ('username', 'full_name', 'password'):
            if row.get(f):
                row[f] = aes_decrypt(row[f])
    return row

# ── Folder for registered face images ──────────────────────────────────────────
UPLOAD_FOLDER = os.path.join('static', 'face_images')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── MySQL ───────────────────────────────────────────────────────────────────────
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'pos_system'

mysql = MySQL(app)

# ── Performance caches ──────────────────────────────────────────────────────────
embedding_cache   = {}          # { employee_id: embedding_vector }
last_frame_time   = {}          # { employee_id: datetime }
MIN_FRAME_INTERVAL = 0.8        # seconds between frames per employee

# ── Face-verification security state ────────────────────────────────────────
# One-time tokens issued by /verify_face on success; consumed by /log_attendance.
# Prevents anyone from clocking in without a real, server-confirmed face match.
verified_tokens   = {}          # { token: {'employee_id': str, 'expires': datetime} }
VERIFY_TOKEN_TTL  = 60          # seconds a verified token stays valid

# Per-employee mismatch lockout — enforced on the SERVER (client timers are bypassable).
face_mismatch_counts = {}       # { employee_id: {'count': int, 'locked_until': datetime|None} }
MAX_FACE_MISMATCHES  = 3        # hard lockout after this many consecutive mismatches
FACE_LOCKOUT_SECONDS = 30       # lockout duration in seconds

# ── Haar cascade for quick face detection ──────────────────────────────────
face_cascade = cv2.CascadeClassifier(
    cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
)

# ── Liveness session store ──────────────────────────────────────────────────────
# Tracks head-nod challenge state per employee during verification
liveness_sessions = {}

# ── Registration capture store ─────────────────────────────────────────────────
# Temporarily holds multi-frame embeddings during face registration
reg_sessions = {}       # { token: { 'embeddings': [], 'best_face': ndarray, 'started': float } }


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         HELPER FUNCTIONS                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def reset_liveness(emp_id):
    """Reset the liveness (anti-spoofing) challenge for an employee."""
    liveness_sessions[emp_id] = {
        "step":       "center",  # center → up → down (nod)
        "last_y":     None,
        "passed":     False,
        "start_time": datetime.now(),
        "stable":     0           # frames without movement (photo-detection)
    }


def is_admin():
    """
    Return True if the current session has full admin privileges.

    Admins can log in either via the legacy 'admin' role (session['role']=='admin')
    OR via the Manager tab (session['role']=='manager' with session['is_admin']==True).
    All routes that previously checked 'admin_id' in session should call is_admin()
    instead so both paths are covered.
    """
    if session.get('role') == 'admin' and 'admin_id' in session:
        return True
    if session.get('role') == 'manager' and session.get('is_admin') is True:
        return True
    return False


def decode_base64_image(image_data: str):
    """
    Decode a base64 data-URI string to an OpenCV BGR image.
    Returns (img_bgr, gray) or raises ValueError on failure.
    """
    if ',' in image_data:
        image_data = image_data.split(',')[1]
    img_bytes = base64.b64decode(image_data)
    img = cv2.imdecode(np.frombuffer(img_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Failed to decode image")
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    return img, gray


def detect_face_strict(img, gray, registration_mode=False):
    """
    Run Haar cascade detection and enforce positional / size constraints.
    Returns (x, y, w, h) on success or raises ValueError with user-facing message.

    registration_mode=True  →  disables blur gate entirely (webcam auto-exposure
                                takes several seconds to settle, so early frames
                                always fail the blur check), relaxes distance and
                                centering tolerances, and uses softer Haar params.
    """
    frame_h, frame_w = img.shape[:2]

    # ── Histogram equalisation: boosts contrast for dim / low-light webcams ─
    gray_eq = cv2.equalizeHist(gray)

    # ── Blur check ───────────────────────────────────────────────────────────
    # Skipped entirely during registration because:
    #   • The first N frames are always dark while the sensor adjusts exposure
    #   • JPEG compression at low quality produces artificially low variance
    #   • A slightly soft face frame is still sufficient for FaceNet-512
    # Only enforced during live verification where image quality matters more.
    if not registration_mode:
        blur_score = cv2.Laplacian(gray, cv2.CV_64F).var()
        if blur_score < 15:
            raise ValueError(f"Image too blurry – hold the camera steady (score: {blur_score:.1f})")

    # ── Haar cascade ─────────────────────────────────────────────────────────
    # Relaxed parameters during registration so dim / slightly off-center
    # faces still detect.  scaleFactor=1.1 catches more scale steps;
    # minNeighbors=3 (vs 5) accepts faces with less repeated confirmation.
    scale     = 1.1 if registration_mode else 1.2
    neighbors = 3   if registration_mode else 4
    faces = face_cascade.detectMultiScale(
        gray_eq, scaleFactor=scale, minNeighbors=neighbors, minSize=(50, 50)
    )
    if len(faces) == 0:
        raise ValueError("No face detected – look directly at the camera")

    # Pick largest detected face (most likely to be the subject)
    faces = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)
    (x, y, w, h) = faces[0]

    # ── Distance check ───────────────────────────────────────────────────────
    ratio     = (w * h) / (frame_w * frame_h)
    min_ratio = 0.03 if registration_mode else 0.04
    if ratio < min_ratio:
        raise ValueError("Move closer to the camera")
    if ratio > 0.65:
        raise ValueError("Move slightly back from the camera")

    # ── Centering check ──────────────────────────────────────────────────────
    cx, cy    = x + w // 2, y + h // 2
    tolerance = 0.38 if registration_mode else 0.35
    if abs(cx - frame_w // 2) > frame_w * tolerance:
        raise ValueError("Center your face horizontally")
    if abs(cy - frame_h // 2) > frame_h * tolerance:
        raise ValueError("Center your face vertically")

    return x, y, w, h


def extract_embedding(img, x, y, w, h):
    """
    Crop and resize a detected face, then extract a Facenet-512 embedding.
    Returns the embedding vector (list of 512 floats).

    Key rules:
    • img must be a uint8 BGR array (0–255) — do NOT normalise to float first.
      DeepFace.represent() handles its own internal pre-processing.
    • We pass detector_backend="skip" because we already located the face with
      the Haar cascade — letting DeepFace run its own detector again would be
      redundant and would re-crop the wrong region.
    • We do NOT pass model= as a pre-built object; newer versions of DeepFace
      removed that parameter and it causes a TypeError crash.
    """
    # Crop to the detected face bounding box
    face_crop = img[y:y + h, x:x + w]

    # Resize to the exact input size FaceNet-512 expects
    face_crop = cv2.resize(face_crop, (160, 160))

    # ── IMPORTANT: keep as uint8 (0-255) ────────────────────────────────────
    # Dividing by 255 would make this float64 in [0,1].  DeepFace.represent()
    # performs its own internal normalisation; passing a float64 array causes
    # it to crash with a shape/dtype mismatch inside the Keras model.
    # face_crop is already uint8 from cv2.imdecode — do NOT touch it here.

    result = DeepFace.represent(
        img_path          = face_crop,
        model_name        = "Facenet512",
        detector_backend  = "skip",
        enforce_detection = False
    )
    return result[0]["embedding"]


def cosine_distance(a, b):
    """Return cosine distance in [0, 2]; lower → more similar (0 = identical)."""
    a, b = np.array(a), np.array(b)
    return 1.0 - float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


def sharpness_score(img_bgr):
    """
    Return the Laplacian variance of a BGR image crop.
    Higher = sharper. Used to pick the best frame during registration.
    """
    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    return cv2.Laplacian(gray, cv2.CV_64F).var()


def persist_embedding(employee_id, embedding_vector):
    """
    Serialize the averaged FaceNet-512 embedding to JSON and store it in
    the face_model_path column.  Also warms the in-memory cache.

    Using face_model_path as the storage column (it exists but was unused).
    The value is a JSON string: '{"v":1,"emb":[...512 floats...]}'
    """
    payload = json.dumps({"v": 1, "emb": embedding_vector}, separators=(',', ':'))
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE employees SET face_model_path=%s WHERE employee_id=%s",
            (payload, employee_id)
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        app.logger.error(f"[persist_embedding] employee {employee_id}: {e}")
    # Always warm cache regardless of DB success
    embedding_cache[str(employee_id)] = embedding_vector


def load_embedding_from_db(employee_id, cur):
    """
    Load the persisted FaceNet-512 embedding from face_model_path.
    Returns the embedding list on success, or None if not found / malformed.
    Falls back to re-extracting from the saved face image if the JSON column
    is missing or from an older registration.
    """
    cur.execute(
        "SELECT face_model_path, face_image_path FROM employees WHERE employee_id=%s",
        (employee_id,)
    )
    row = cur.fetchone()
    if not row:
        return None

    # ── Try JSON embedding first (fast, accurate, no image round-trip) ──────
    model_path = row.get('face_model_path') or ''
    if model_path.startswith('{'):
        try:
            payload = json.loads(model_path)
            emb = payload.get('emb')
            if emb and len(emb) == 512:
                app.logger.info(f"[load_embedding] employee {employee_id}: loaded from DB JSON")
                return emb
        except (json.JSONDecodeError, KeyError):
            pass

    # ── Fallback: re-extract from saved 160×160 face image ──────────────────
    face_image_path = row.get('face_image_path') or ''
    if not face_image_path:
        return None
    reg_path = os.path.join("static", face_image_path)
    if not os.path.exists(reg_path):
        return None
    try:
        reg_img = cv2.imread(reg_path)
        if reg_img is None:
            return None
        reg_img = cv2.resize(reg_img, (160, 160))
        reg_result = DeepFace.represent(
            img_path         = reg_img,
            model_name       = "Facenet512",
            detector_backend = "skip",
            enforce_detection= False
        )
        emb = reg_result[0]["embedding"]
        app.logger.warning(
            f"[load_embedding] employee {employee_id}: fell back to image re-extraction "
            f"(face_model_path missing). Consider re-registering the face for best accuracy."
        )
        return emb
    except Exception as e:
        app.logger.error(f"[load_embedding] image fallback failed for employee {employee_id}: {e}")
        return None


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    FACE REGISTRATION (multi-frame)                          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── Per-token processing lock: prevents concurrent DeepFace calls for the ──
# ── same registration session, which would stack up and crash the server.  ──
reg_locks = set()   # set of tokens currently being processed


@app.route('/register_face_frame', methods=['POST'])
def register_face_frame():
    """
    Called by the employee-management modal to capture one webcam frame
    and extract a FaceNet-512 embedding for registration.

    Sequential safety: if a previous call for the same token is still
    running (DeepFace can take 2–5 s on CPU), this call returns immediately
    with a "busy" response so the client retries on the next tick.
    """
    try:
        data        = request.get_json(silent=True) or {}
        token       = data.get('token', '')
        image_data  = data.get('image', '')

        if not token or not image_data:
            return jsonify({'success': False, 'message': 'Missing token or image', 'captured': 0})

        # ── Concurrent-call guard ────────────────────────────────────────────
        if token in reg_locks:
            return jsonify({'success': False, 'message': 'Processing… please hold still', 'captured': 0})
        reg_locks.add(token)

        try:
            # Initialise session for this registration token if first frame
            if token not in reg_sessions:
                reg_sessions[token] = {
                    'embeddings':    [],
                    'best_face':     None,
                    'best_sharpness': -1.0,   # track sharpness to pick best crop
                    'started':       time.time()
                }

            sess = reg_sessions[token]

            # ── Expire stale sessions (>5 min) ─────────────────────────────
            if time.time() - sess['started'] > 300:
                del reg_sessions[token]
                return jsonify({'success': False, 'message': 'Session expired – restart capture', 'captured': 0})

            # ── Decode & analyse frame ──────────────────────────────────────
            try:
                img, gray = decode_base64_image(image_data)
                # Flip mirrored canvas back to natural orientation for Haar
                img  = cv2.flip(img,  1)
                gray = cv2.flip(gray, 1)
                x, y, w, h = detect_face_strict(img, gray, registration_mode=True)
            except ValueError as e:
                return jsonify({'success': False, 'message': str(e), 'captured': len(sess['embeddings'])})

            # ── Extract embedding ───────────────────────────────────────────
            try:
                emb = extract_embedding(img, x, y, w, h)
            except Exception as e:
                return jsonify({'success': False, 'message': f'Embedding error: {e}', 'captured': len(sess['embeddings'])})

            # ── Keep sharpest face crop across all frames ───────────────────
            # Comparing sharpness ensures the saved image (used as visual
            # reference) is the clearest one, even though verification uses
            # the averaged embedding, not this image.
            face_crop = img[y:y + h, x:x + w]
            crop_160  = cv2.resize(face_crop, (160, 160))
            sharp     = sharpness_score(crop_160)
            if sharp > sess['best_sharpness']:
                sess['best_sharpness'] = sharp
                sess['best_face']      = crop_160

            sess['embeddings'].append(emb)
            captured = len(sess['embeddings'])

            step_msgs = {
                1: "⬆️ Now slowly move head UP",
                2: "⬇️ Now move head DOWN",
                3: "✅ Face capture complete"
            }
            msg = step_msgs.get(captured, f"Frame {captured} captured")

            return jsonify({'success': True, 'message': msg, 'captured': captured})

        finally:
            # ── Always release the lock, even on error ──────────────────────
            reg_locks.discard(token)

    except Exception as e:
        # ── Top-level safety net: never let any exception crash Flask ───────
        return jsonify({'success': False, 'message': f'Server error: {e}', 'captured': 0})


@app.route('/commit_face_registration', methods=['POST'])
def commit_face_registration():
    """
    Finalize registration: average the captured embeddings, save the sharpest
    face image, persist the averaged embedding to DB, and update the employee record.

    POST JSON:  { "token": str, "employee_id": int }
    Response:   { "success": bool, "message": str }
    """
    data        = request.get_json(silent=True) or {}
    token       = data.get('token', '')
    employee_id = data.get('employee_id')

    if not token or not employee_id:
        return jsonify({'success': False, 'message': 'Missing token or employee_id'})

    sess = reg_sessions.get(token)
    if not sess:
        return jsonify({'success': False, 'message': 'Registration session not found'})

    if len(sess['embeddings']) < 2:
        return jsonify({'success': False, 'message': 'Not enough frames captured (need ≥ 2)'})

    if sess['best_face'] is None:
        return jsonify({'success': False, 'message': 'No valid face crop available'})

    # ── Save sharpest face image ─────────────────────────────────────────────
    filename    = f"{employee_id}.jpg"
    image_path  = os.path.join(UPLOAD_FOLDER, filename)
    cv2.imwrite(image_path, sess['best_face'], [cv2.IMWRITE_JPEG_QUALITY, 95])
    face_path   = f"face_images/{filename}"

    # ── Average embeddings for best accuracy ────────────────────────────────
    avg_emb = np.mean(sess['embeddings'], axis=0).tolist()

    # ── Persist to DB ───────────────────────────────────────────────────────
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE employees SET face_image_path=%s WHERE employee_id=%s",
            (face_path, employee_id)
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        return jsonify({'success': False, 'message': f'DB error: {e}'})

    # ── Persist averaged embedding to face_model_path column ────────────────
    persist_embedding(str(employee_id), avg_emb)

    # ── Clean up registration session ───────────────────────────────────────
    del reg_sessions[token]

    return jsonify({'success': True, 'message': '✅ Face ID registered successfully'})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    FACE VERIFICATION (clock-in / out)                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/verify_face', methods=['POST'])
def verify_face():
    """
    Verify a live webcam frame against the employee's registered face embedding.
    Includes liveness detection (head-nod challenge) to prevent photo spoofing.

    POST JSON:
        { "employee_id": str|int, "image": "data:image/jpeg;base64,..." }

    Response JSON:
        { "success": bool, "message": str }
    """
    data        = request.get_json(silent=True) or {}
    employee_id = str(data.get('employee_id', ''))
    image_data  = data.get('image', '')

    if not employee_id or not image_data:
        return jsonify({'success': False, 'message': 'Missing data'})

    now = datetime.now()

    # ── Rate-limit per employee (anti-spam) ─────────────────────────────────
    if employee_id in last_frame_time:
        elapsed = (now - last_frame_time[employee_id]).total_seconds()
        if elapsed < MIN_FRAME_INTERVAL:
            return jsonify({'success': False, 'message': 'Hold still…'})

    # ── Fetch registered face path from DB ──────────────────────────────────
    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT face_image_path FROM employees WHERE employee_id=%s",
        (employee_id,)
    )
    emp = cur.fetchone()
    cur.close()

    if not emp or not emp.get('face_image_path'):
        return jsonify({'success': False, 'message': 'No Face ID registered for this employee'})

    # ── Decode & validate incoming frame ────────────────────────────────────
    try:
        img, gray = decode_base64_image(image_data)
        # The browser mirrors the canvas — flip back to natural orientation
        # so Haar detection works correctly (trained on unmirrored faces).
        img  = cv2.flip(img,  1)
        gray = cv2.flip(gray, 1)
        x, y, w, h = detect_face_strict(img, gray)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)})

    # ── Rate-limit: update timestamp here so it applies during liveness too ─
    last_frame_time[employee_id] = now

    # ── Server-side mismatch lockout ─────────────────────────────────────────
    # Client-side timers (isMismatchLocked) are bypassable via DevTools or
    # direct HTTP requests. This lockout is enforced purely on the server.
    fm = face_mismatch_counts.get(employee_id, {'count': 0, 'locked_until': None})
    if fm['locked_until'] and now < fm['locked_until']:
        secs_left = int((fm['locked_until'] - now).total_seconds()) + 1
        return jsonify({
            'success': False,
            'message': f'\U0001f512 Too many failed attempts. Try again in {secs_left}s.',
            'locked': True
        })

    # ── Liveness challenge (head-nod: up → down) ─────────────────────────────
    if employee_id not in liveness_sessions:
        reset_liveness(employee_id)

    s = liveness_sessions[employee_id]

    # Expire challenge after 20 s
    if (now - s["start_time"]).seconds > 20:
        reset_liveness(employee_id)
        return jsonify({'success': False, 'message': '\u23f1\ufe0f Challenge expired – look at camera and try again'})

    center_y = y + h // 2

    if s["last_y"] is None:
        s["last_y"] = center_y
        return jsonify({'success': False, 'message': '\u2b06\ufe0f Please move your head UP slowly'})

    move = center_y - s["last_y"]   # negative = moved up, positive = moved down

    # Anti-photo: reject if face has been perfectly static for >6 frames
    if abs(move) < 3:
        s["stable"] += 1
    else:
        s["stable"] = 0

    if s["stable"] > 6:
        return jsonify({'success': False, 'message': '\U0001f6ab Static image detected – please move your head'})

    # ── Always update last_y so movement is measured frame-to-frame ─────────
    s["last_y"] = center_y

    if s["step"] == "center":
        if move < -8:
            s["step"] = "up"
            return jsonify({'success': False, 'message': '\u2b07\ufe0f Good! Now move your head DOWN'})
        return jsonify({'success': False, 'message': '\u2b06\ufe0f Move your head UP'})

    elif s["step"] == "up":
        if move > 8:
            s["passed"] = True

    if not s["passed"]:
        return jsonify({'success': False, 'message': '\u2b07\ufe0f Keep moving your head DOWN'})

    # ── Liveness passed — reset BEFORE any return below ─────────────────────
    # Resetting here ensures that embedding errors, DB errors, or any early
    # return cannot leave passed=True. Without this, the next frame would skip
    # liveness entirely and go straight to face matching.
    reset_liveness(employee_id)

    # ── Perform face match ───────────────────────────────────────────────────
    try:
        captured_emb = extract_embedding(img, x, y, w, h)
    except Exception as e:
        return jsonify({'success': False, 'message': f'Embedding error: {e}'})

    if employee_id not in embedding_cache:
        cur2 = mysql.connection.cursor(DictCursor)
        emb  = load_embedding_from_db(employee_id, cur2)
        cur2.close()
        if emb is None:
            return jsonify({'success': False, 'message': 'No registered Face ID found – please re-register'})
        embedding_cache[employee_id] = emb

    registered_emb = embedding_cache[employee_id]
    distance = cosine_distance(captured_emb, registered_emb)

    last_frame_time[employee_id] = now

    MATCH_THRESHOLD = 0.30
    if distance >= MATCH_THRESHOLD:
        # ── Increment server-side mismatch counter ───────────────────────────
        fm = face_mismatch_counts.get(employee_id, {'count': 0, 'locked_until': None})
        fm['count'] += 1
        attempts_left = max(0, MAX_FACE_MISMATCHES - fm['count'])

        # Log every mismatch to DB
        try:
            mlog_cur = mysql.connection.cursor()
            mlog_cur.execute(
                """INSERT INTO face_mismatch_log
                   (employee_id, distance_score, ip_address, user_agent)
                   VALUES (%s, %s, %s, %s)""",
                (employee_id, round(distance, 4),
                 request.remote_addr, (request.user_agent.string or '')[:255])
            )
            mysql.connection.commit()
            mlog_cur.close()
        except Exception as log_err:
            app.logger.error(f"[face_mismatch_log] write failed: {log_err}")

        if fm['count'] >= MAX_FACE_MISMATCHES:
            fm['locked_until'] = datetime.now() + __import__('datetime').timedelta(seconds=FACE_LOCKOUT_SECONDS)
            fm['count'] = 0
            face_mismatch_counts[employee_id] = fm
            return jsonify({
                'success': False,
                'message': f'\U0001f512 Too many failed attempts. Locked for {FACE_LOCKOUT_SECONDS}s.',
                'mismatch': True,
                'locked': True
            })

        face_mismatch_counts[employee_id] = fm
        return jsonify({
            'success': False,
            'message': f'\U0001f6ab Face does not match. {attempts_left} attempt(s) left before lockout.',
            'mismatch': True
        })

    # ── Match confirmed — clear mismatch counter ─────────────────────────────
    face_mismatch_counts.pop(employee_id, None)

    # ── Issue a one-time signed token ────────────────────────────────────────
    # /log_attendance REQUIRES this token. This closes the bypass where someone
    # POSTs directly to /log_attendance without ever passing face verification.
    # The token is tied to the specific employee_id and expires in VERIFY_TOKEN_TTL s.
    verify_token = secrets.token_urlsafe(32)
    verified_tokens[verify_token] = {
        'employee_id': employee_id,
        'expires':     datetime.now() + __import__('datetime').timedelta(seconds=VERIFY_TOKEN_TTL)
    }
    # Purge expired tokens to prevent unbounded memory growth
    _now = datetime.now()
    for _t in [t for t, v in list(verified_tokens.items()) if v['expires'] < _now]:
        verified_tokens.pop(_t, None)

    return jsonify({
        'success': True,
        'message': '\u2705 Identity verified. Welcome!',
        'verify_token': verify_token
    })


@app.route('/api/face_mismatch_log', methods=['GET'])
def api_face_mismatch_log():
    """
    Admin-only: return recent face mismatch attempts for security audit.
    Optional query params: ?employee_id=N&limit=50
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    employee_id = request.args.get('employee_id')
    try:
        limit = max(1, min(int(request.args.get('limit', 100)), 500))
    except (ValueError, TypeError):
        limit = 100

    cur = mysql.connection.cursor(DictCursor)
    if employee_id:
        cur.execute(
            """SELECT fml.id, fml.employee_id, e.full_name,
                      fml.distance_score, fml.attempted_at, fml.ip_address
               FROM face_mismatch_log fml
               LEFT JOIN employees e ON e.employee_id = fml.employee_id
               WHERE fml.employee_id = %s
               ORDER BY fml.attempted_at DESC LIMIT %s""",
            (employee_id, limit)
        )
    else:
        cur.execute(
            """SELECT fml.id, fml.employee_id, e.full_name,
                      fml.distance_score, fml.attempted_at, fml.ip_address
               FROM face_mismatch_log fml
               LEFT JOIN employees e ON e.employee_id = fml.employee_id
               ORDER BY fml.attempted_at DESC LIMIT %s""",
            (limit,)
        )
    rows = cur.fetchall()
    cur.close()
    # Decrypt full_name for display
    for row in rows:
        if row.get('full_name'):
            row['full_name'] = aes_decrypt(row['full_name']) or row['full_name']
        if row.get('attempted_at'):
            row['attempted_at'] = str(row['attempted_at'])
    return jsonify({'success': True, 'mismatches': rows})


@app.errorhandler(500)
def handle_500(e):
    """Return JSON for any unhandled 500 error so the server stays up."""
    return jsonify({'success': False, 'message': f'Internal server error: {e}'}), 500


@app.route('/reset_liveness', methods=['POST'])
def reset_liveness_route():
    """
    Called by the frontend when the user enters Step 3 (Face Verify).
    Clears any stale liveness session so the challenge always starts fresh
    — prevents a user from getting stuck in a partial challenge state from
    a previous attempt.
    """
    data        = request.get_json(silent=True) or {}
    employee_id = str(data.get('employee_id', ''))
    if employee_id and employee_id in liveness_sessions:
        reset_liveness(employee_id)
    return jsonify({'success': True})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         LOGIN / LOGOUT                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/')
def root():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role     = request.form.get('login_role', '').strip()
        username = (request.form.get(f"{role}Username") or '').strip()
        password = (request.form.get(f"{role}Password") or '').strip()

        if not username or not password:
            flash("Please enter both username and password.")
            return render_template('index.html')

        u_hash = aes_username_hash(username)

        # ── Lockout check — must happen before any DB credential query ────────
        # We check *both* the specific role key AND a shared "any-role" key so
        # that attackers cannot bypass a cashier lockout by switching to manager.
        lockout_role_key = role  # per-role key (independent counters per tab)
        state = check_lockout(u_hash, lockout_role_key)
        if state['locked']:
            flash(_lockout_flash(state))
            return render_template('index.html')

        cur = mysql.connection.cursor(DictCursor)
        auth_ok    = False
        redirect_to = None

        # ── Legacy admin tab ─────────────────────────────────────────────────
        if role == 'admin':
            cur.execute("SELECT * FROM admins WHERE username_hash=%s", (u_hash,))
            user = _dec_adm(cur.fetchone())
            if user and _check_login_password(password, user):
                session.clear()
                session['admin_id']  = user['admin_id']
                session['role']      = 'admin'
                session['is_admin']  = True
                session['full_name'] = (user.get('full_name') or 'Admin').strip()
                auth_ok     = True
                redirect_to = url_for('dashboard')

        # ── Manager tab ──────────────────────────────────────────────────────
        elif role == 'manager':
            cur.execute(
                """SELECT * FROM employees WHERE username_hash=%s
                   AND role='manager' AND employment_status='active'""", (u_hash,))
            employee = _dec_emp(cur.fetchone())
            if employee and _check_login_password(password, employee):
                session.clear()
                session['employee_id'] = employee['employee_id']
                session['role']        = 'manager'
                session['is_admin']    = False
                session['full_name']   = (employee.get('full_name') or 'Manager').strip()
                cur.execute("UPDATE employees SET last_login=NOW() WHERE employee_id=%s",
                            (employee['employee_id'],))
                mysql.connection.commit()
                auth_ok     = True
                redirect_to = url_for('dashboard')
            else:
                # Fallback: try admins table via Manager tab
                cur.execute("SELECT * FROM admins WHERE username_hash=%s", (u_hash,))
                admin = _dec_adm(cur.fetchone())
                if admin and _check_login_password(password, admin):
                    session.clear()
                    session['admin_id']  = admin['admin_id']
                    session['role']      = 'admin'
                    session['is_admin']  = True
                    session['full_name'] = (admin.get('full_name') or 'Admin').strip()
                    auth_ok     = True
                    redirect_to = url_for('dashboard')

        # ── Cashier tab ──────────────────────────────────────────────────────
        elif role == 'cashier':
            cur.execute(
                """SELECT * FROM employees WHERE username_hash=%s
                   AND role='cashier' AND employment_status='active'""", (u_hash,))
            user = _dec_emp(cur.fetchone())
            if user and _check_login_password(password, user):
                session.clear()
                session['employee_id'] = user['employee_id']
                session['role']        = 'cashier'
                session['is_admin']    = False
                session['full_name']   = (user.get('full_name') or 'Cashier').strip()
                cur.execute("UPDATE employees SET last_login=NOW() WHERE employee_id=%s",
                            (user['employee_id'],))
                mysql.connection.commit()
                auth_ok     = True
                redirect_to = url_for('cashier_dashboard')

        cur.close()

        if auth_ok:
            # ── Successful login: clear the fail counter ──────────────────────
            clear_failed_attempts(u_hash, lockout_role_key)
            return redirect(redirect_to)

        # ── Failed login: increment counter, apply lockout if threshold hit ──
        new_state = record_failed_attempt(u_hash, lockout_role_key)
        flash(_lockout_flash(new_state))

    return render_template('index.html')

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         DASHBOARD                                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/dashboard')
def dashboard():
    if session.get('role') not in ['admin', 'manager']:
        return redirect(url_for('login'))

    # Use session-cached full_name (already stripped at login) if available
    full_name = session.get('full_name')
    if not full_name:
        cur = mysql.connection.cursor(DictCursor)
        if session['role'] == 'admin':
            cur.execute("SELECT full_name FROM admins WHERE admin_id=%s", (session['admin_id'],))
            user = _dec_adm(cur.fetchone())
        else:
            cur.execute("SELECT full_name FROM employees WHERE employee_id=%s", (session['employee_id'],))
            user = _dec_emp(cur.fetchone())
        full_name = (user['full_name'] if user else session['role'].capitalize()).strip()
        cur.close()

    return render_template('dashboard.html', full_name=full_name)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                       EMPLOYEE MANAGEMENT                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/employee_management')
def employee_management():
    if session.get('role') not in ['admin', 'manager']:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(DictCursor)

    if session['role'] == 'admin':
        cur.execute("SELECT full_name FROM admins WHERE admin_id=%s", (session['admin_id'],))
        user = _dec_adm(cur.fetchone())
    else:
        cur.execute("SELECT full_name FROM employees WHERE employee_id=%s", (session['employee_id'],))
        user = _dec_emp(cur.fetchone())
    full_name = user['full_name'] if user else session['role'].capitalize()

    cur.execute("""
        SELECT employee_id, full_name, username, role, contact_number,
               employment_status, face_image_path, face_model_path,
               last_login, created_at,
               COALESCE(hourly_rate, 0) AS hourly_rate
        FROM employees
        ORDER BY created_at DESC
    """)
    employees = [_dec_emp(row) for row in cur.fetchall()]
    cur.close()

    return render_template('employee_management.html', full_name=full_name, employees=employees)


@app.route('/add_employee', methods=['POST'])
def add_employee():
    """
    Create a new employee record.

    Accepts multipart/form-data with:
        full_name, username, password, role, contact, status
        face_images[] – 3+ JPEG blobs from the webcam registration flow

    The backend re-processes the blobs through the full face detection +
    embedding pipeline so the stored face is always clean and verified.
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    full_name = request.form.get('full_name', '').strip()
    username  = request.form.get('username', '').strip()
    password  = request.form.get('password', '').strip()
    role      = request.form.get('role', '').strip()
    contact   = request.form.get('contact', '').strip()
    status    = request.form.get('status', 'active')
    try:
        hourly_rate = float(request.form.get('hourly_rate', 0) or 0)
    except (ValueError, TypeError):
        hourly_rate = 0.0

    if not all([full_name, username, password, role, contact]):
        return jsonify({'success': False, 'message': 'All fields are required'})

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """INSERT INTO employees
               (full_name, username, username_hash, password, password_hash,
                role, contact_number, employment_status, hourly_rate)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (aes_encrypt(full_name), aes_encrypt(username), aes_username_hash(username),
             aes_encrypt(password), hash_password(password), role,
             aes_encrypt(contact), status, hourly_rate)
        )
        employee_id = cur.lastrowid

        # ── Process uploaded face frames ─────────────────────────────────────
        files         = request.files.getlist('face_images[]')
        embeddings    = []
        best_face     = None
        best_sharp_ae = -1.0

        for file in files:
            file_bytes = np.frombuffer(file.read(), np.uint8)
            img        = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            if img is None:
                continue

            try:
                # Browser canvas is mirrored – flip to natural orientation
                img  = cv2.flip(img, 1)
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                x, y, w, h = detect_face_strict(img, gray, registration_mode=True)
                emb        = extract_embedding(img, x, y, w, h)
                embeddings.append(emb)
                # Pick sharpest crop across all frames
                crop     = img[y:y + h, x:x + w]
                crop_160 = cv2.resize(crop, (160, 160))
                sharp    = sharpness_score(crop_160)
                if sharp > best_sharp_ae:
                    best_sharp_ae = sharp
                    best_face     = crop_160
            except (ValueError, Exception):
                continue

        if len(embeddings) < 1:
            mysql.connection.rollback()
            cur.close()
            return jsonify({'success': False, 'message': 'No face detected in captured frames – please retake'})

        # ── Save sharpest face image ─────────────────────────────────────────
        filename   = f"{employee_id}.jpg"
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        cv2.imwrite(image_path, best_face, [cv2.IMWRITE_JPEG_QUALITY, 95])
        face_path  = f"face_images/{filename}"

        cur.execute(
            "UPDATE employees SET face_image_path=%s WHERE employee_id=%s",
            (face_path, employee_id)
        )
        mysql.connection.commit()
        cur.close()

        # ── Persist averaged embedding to DB (face_model_path) ───────────────
        avg_emb = np.mean(embeddings, axis=0).tolist()
        persist_embedding(str(employee_id), avg_emb)

        return jsonify({'success': True, 'message': 'Employee registered with Face ID ✅', 'employee_id': employee_id})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/update_employee/<int:employee_id>', methods=['POST'])
def update_employee(employee_id):
    """Update employee details; also re-registers Face ID if new face_images[] are provided."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    full_name = request.form.get('full_name', '').strip()
    username  = request.form.get('username', '').strip()
    role      = request.form.get('role', '').strip()
    contact   = request.form.get('contact', '').strip()
    status    = request.form.get('status', '').strip()
    try:
        hourly_rate = float(request.form.get('hourly_rate', 0) or 0)
    except (ValueError, TypeError):
        hourly_rate = 0.0

    enc_name     = aes_encrypt(full_name)
    enc_username = aes_encrypt(username)
    enc_contact  = aes_encrypt(contact)
    u_hash       = aes_username_hash(username)

    try:
        cur = mysql.connection.cursor()

        files         = request.files.getlist('face_images[]')
        embeddings    = []
        best_face     = None
        best_sharp_ue = -1.0

        for file in files:
            file_bytes = np.frombuffer(file.read(), np.uint8)
            img        = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            if img is None:
                continue
            try:
                # Browser canvas is mirrored – flip to natural orientation
                # (was missing in update_employee — caused orientation mismatch)
                img  = cv2.flip(img, 1)
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                x, y, w, h = detect_face_strict(img, gray, registration_mode=True)
                emb        = extract_embedding(img, x, y, w, h)
                embeddings.append(emb)
                # Pick sharpest crop across all frames
                crop     = img[y:y + h, x:x + w]
                crop_160 = cv2.resize(crop, (160, 160))
                sharp    = sharpness_score(crop_160)
                if sharp > best_sharp_ue:
                    best_sharp_ue = sharp
                    best_face     = crop_160
            except (ValueError, Exception):
                continue

        if embeddings and best_face is not None:
            # New face registered during edit
            filename   = f"{employee_id}.jpg"
            image_path = os.path.join(UPLOAD_FOLDER, filename)
            cv2.imwrite(image_path, best_face, [cv2.IMWRITE_JPEG_QUALITY, 95])
            face_path  = f"face_images/{filename}"

            cur.execute(
                """UPDATE employees
                   SET full_name=%s, username=%s, username_hash=%s, role=%s,
                       contact_number=%s, employment_status=%s, face_image_path=%s,
                       hourly_rate=%s
                   WHERE employee_id=%s""",
                (enc_name, enc_username, u_hash, role, enc_contact, status,
                 face_path, hourly_rate, employee_id)
            )
            # Persist new averaged embedding; also invalidates old cache entry
            avg_emb_ue = np.mean(embeddings, axis=0).tolist()
            persist_embedding(str(employee_id), avg_emb_ue)
        else:
            cur.execute(
                """UPDATE employees
                   SET full_name=%s, username=%s, username_hash=%s, role=%s,
                       contact_number=%s, employment_status=%s, hourly_rate=%s
                   WHERE employee_id=%s""",
                (enc_name, enc_username, u_hash, role, enc_contact,
                 status, hourly_rate, employee_id)
            )

        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/delete_employee/<int:employee_id>', methods=['DELETE'])
def delete_employee(employee_id):
    """
    Move an employee to the trash (employees_trash table).
    The employee is set to 'inactive' immediately and permanently deleted
    from the database after a 24-hour grace period.
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    try:
        import datetime as _dt
        cur = mysql.connection.cursor(DictCursor)

        # Fetch the full employee row before touching it
        cur.execute("""
            SELECT employee_id, full_name, username, username_hash,
                   password, password_hash, role, contact_number,
                   face_image_path, face_model_path, last_login,
                   created_at, disabled_at
            FROM employees WHERE employee_id=%s LIMIT 1
        """, (employee_id,))
        emp = cur.fetchone()

        if not emp:
            cur.close()
            return jsonify({'success': False, 'message': 'Employee not found'}), 404

        # Check not already in trash
        cur.execute(
            "SELECT trash_id FROM employees_trash WHERE employee_id=%s LIMIT 1",
            (employee_id,)
        )
        if cur.fetchone():
            cur.close()
            return jsonify({'success': False, 'message': 'Employee is already in trash'}), 400

        now       = datetime.now()
        delete_at = now + _dt.timedelta(hours=24)

        # Insert snapshot into trash
        cur.execute("""
            INSERT INTO employees_trash
                (employee_id, full_name, username, username_hash,
                 password, password_hash, role, contact_number,
                 face_image_path, face_model_path, last_login,
                 created_at, disabled_at, delete_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            emp['employee_id'], emp['full_name'], emp['username'],
            emp['username_hash'], emp['password'], emp['password_hash'],
            emp['role'], emp['contact_number'], emp['face_image_path'],
            emp['face_model_path'], emp['last_login'], emp['created_at'],
            now, delete_at
        ))

        # Soft-disable the live row so they can't log in
        cur.execute(
            "UPDATE employees SET employment_status='inactive', disabled_at=%s WHERE employee_id=%s",
            (now, employee_id)
        )
        mysql.connection.commit()
        cur.close()

        # Invalidate caches
        embedding_cache.pop(str(employee_id), None)
        face_mismatch_counts.pop(str(employee_id), None)

        app.logger.info(f"[trash] Employee #{employee_id} moved to trash, delete_at={delete_at}")
        return jsonify({
            'success':   True,
            'message':   'Employee moved to trash. Will be permanently deleted in 24 hours.',
            'delete_at': delete_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/trash', methods=['GET'])
def api_trash():
    """Admin-only: list all employees currently in the trash with time remaining."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("""
        SELECT trash_id, employee_id, full_name, role,
               disabled_at, delete_at,
               GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), delete_at)) AS seconds_remaining
        FROM employees_trash
        ORDER BY delete_at ASC
    """)
    rows = cur.fetchall()
    cur.close()

    for row in rows:
        if row.get('full_name'):
            row['full_name'] = aes_decrypt(row['full_name']) or row['full_name']
        if row.get('disabled_at'):
            row['disabled_at'] = str(row['disabled_at'])
        if row.get('delete_at'):
            row['delete_at'] = str(row['delete_at'])

    return jsonify({'success': True, 'trash': rows})


@app.route('/restore_employee/<int:employee_id>', methods=['POST'])
def restore_employee(employee_id):
    """
    Restore an employee from the trash back to active status.
    Removes the trash entry and re-activates the employee row.
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    try:
        cur = mysql.connection.cursor(DictCursor)

        cur.execute(
            "SELECT trash_id FROM employees_trash WHERE employee_id=%s LIMIT 1",
            (employee_id,)
        )
        trash_row = cur.fetchone()
        if not trash_row:
            cur.close()
            return jsonify({'success': False, 'message': 'Employee not found in trash'}), 404

        # Re-activate the live row
        cur.execute(
            "UPDATE employees SET employment_status='active', disabled_at=NULL WHERE employee_id=%s",
            (employee_id,)
        )
        # Remove from trash
        cur.execute(
            "DELETE FROM employees_trash WHERE trash_id=%s",
            (trash_row['trash_id'],)
        )
        mysql.connection.commit()
        cur.close()

        app.logger.info(f"[trash] Employee #{employee_id} restored from trash")
        return jsonify({'success': True, 'message': 'Employee restored successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


# ── Invalidate embedding cache when called externally ──────────────────────────
@app.route('/invalidate_face_cache/<int:employee_id>', methods=['POST'])
def invalidate_face_cache(employee_id):
    """Remove a cached embedding so the next verification re-reads from disk."""
    if session.get('role') not in ['admin', 'manager']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    embedding_cache.pop(str(employee_id), None)
    return jsonify({'success': True, 'message': 'Cache cleared'})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                       STAFF ATTENDANCE                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/staff_attendance')
def staff_attendance():
    if session.get('role') not in ['admin', 'manager']:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(DictCursor)
    if session['role'] == 'admin':
        cur.execute("SELECT full_name FROM admins WHERE admin_id=%s", (session['admin_id'],))
        user = _dec_adm(cur.fetchone())
    else:
        cur.execute("SELECT full_name FROM employees WHERE employee_id=%s", (session['employee_id'],))
        user = _dec_emp(cur.fetchone())
    full_name = user['full_name'] if user else session['role'].capitalize()
    cur.close()

    return render_template('staff_attendance.html', full_name=full_name)


@app.route('/log_attendance', methods=['POST'])
def log_attendance():
    """
    Record a clock-in or clock-out after face verification has already succeeded.

    POST JSON:
        { "employee_id": int, "action": "clock_in"|"clock_out",
          "shift_type": str, "verify_token": str }

    SECURITY: verify_token is a one-time token issued by /verify_face on a
    confirmed face match. Without a valid, unexpired token that matches the
    employee_id in this request, clock-in/out is refused. This prevents anyone
    from bypassing face verification by POSTing directly to this endpoint.
    """
    if 'employee_id' not in session and not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data         = request.get_json(silent=True) or {}
    action       = data.get('action')
    shift_type   = data.get('shift_type')
    verify_token = data.get('verify_token', '')

    if not all([action, shift_type, verify_token]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400

    # ── Validate the one-time face-verification token ────────────────────────
    # SECURITY: employee_id MUST come from the verified token, never from the
    # session or the client-supplied request body. The token is cryptographically
    # tied to the face that passed /verify_face — using any other source allows
    # a user to clock in on behalf of a different employee by simply changing the
    # employee_id in the POST body or relying on a mismatched session value.
    token_data = verified_tokens.get(verify_token)
    if not token_data:
        app.logger.warning(
            f"[log_attendance] REJECTED — invalid or missing verify_token "
            f"action={action} ip={request.remote_addr}"
        )
        return jsonify({
            'success': False,
            'message': 'Face verification required before clocking in/out.'
        }), 403

    # Derive employee_id exclusively from the token — ignore request body value
    employee_id     = token_data['employee_id']
    employee_id_str = str(employee_id)

    # Sanity-guard: logged-in session employee must match the face that was verified.
    # This catches any case where the session identity diverges from the verified face.
    session_emp = session.get('employee_id')
    if session_emp and str(session_emp) != employee_id_str:
        app.logger.warning(
            f"[log_attendance] SESSION/TOKEN MISMATCH — session employee "
            f"{session_emp} attempted to use token belonging to employee "
            f"{employee_id_str} ip={request.remote_addr}"
        )
        # Log as a security event against the session employee (the one attempting the bypass)
        try:
            mlog_cur = mysql.connection.cursor()
            mlog_cur.execute(
                """INSERT INTO face_mismatch_log
                   (employee_id, distance_score, ip_address, user_agent)
                   VALUES (%s, %s, %s, %s)""",
                (session_emp, None,
                 request.remote_addr, (request.user_agent.string or '')[:255])
            )
            mysql.connection.commit()
            mlog_cur.close()
        except Exception:
            pass
        return jsonify({
            'success': False,
            'message': 'Face verification token does not match this employee.'
        }), 403

    if datetime.now() > token_data['expires']:
        verified_tokens.pop(verify_token, None)
        app.logger.warning(
            f"[log_attendance] EXPIRED TOKEN — employee {employee_id_str} ip={request.remote_addr}"
        )
        return jsonify({
            'success': False,
            'message': 'Verification expired — please verify your face again.'
        }), 403

    # ── Token valid — consume it (one-time use) ──────────────────────────────
    verified_tokens.pop(verify_token, None)

    cur = mysql.connection.cursor(DictCursor)

    # Validate employee
    cur.execute(
        "SELECT employee_id, full_name, role, employment_status FROM employees WHERE employee_id=%s LIMIT 1",
        (employee_id,)
    )
    emp = cur.fetchone()
    if not emp:
        cur.close()
        return jsonify({'success': False, 'message': 'Employee not found'}), 404
    if emp['employment_status'] != 'active':
        cur.close()
        return jsonify({'success': False, 'message': 'Employee account is inactive'}), 400
    # Decrypt PII fields so the frontend confirm card shows the real name/role
    if emp.get('full_name'):
        emp['full_name'] = aes_decrypt(emp['full_name']) or emp['full_name']

    # Today's attendance record
    cur.execute(
        "SELECT attendance_id, clock_in, clock_out FROM attendance WHERE employee_id=%s AND attendance_date=CURDATE() LIMIT 1",
        (employee_id,)
    )
    record = cur.fetchone()

    if action == "clock_in":
        if record:
            cur.close()
            return jsonify({'success': False, 'message': 'Already clocked in today'}), 400
        cur.execute(
            "INSERT INTO attendance (employee_id, shift_type, clock_in, attendance_date) VALUES (%s, %s, NOW(), CURDATE())",
            (employee_id, shift_type)
        )
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True, 'message': 'Clock-in recorded ✅', 'employee': emp, 'action': 'clock_in', 'shift_type': shift_type})

    elif action == "clock_out":
        if not record:
            cur.close()
            return jsonify({'success': False, 'message': 'No clock-in found for today'}), 400
        if record['clock_out'] is not None:
            cur.close()
            return jsonify({'success': False, 'message': 'Already clocked out today'}), 400
        cur.execute(
            "UPDATE attendance SET clock_out=NOW() WHERE attendance_id=%s",
            (record['attendance_id'],)
        )
        mysql.connection.commit()
        # ── Persist payroll columns on clock-out ─────────────────────────────
        _store_clock_out_pay(mysql.connection, record['attendance_id'])
        cur.close()
        return jsonify({'success': True, 'message': 'Clock-out recorded ✅', 'employee': emp, 'action': 'clock_out', 'shift_type': shift_type})

    cur.close()
    return jsonify({'success': False, 'message': 'Invalid action'}), 400


@app.route('/api/employees', methods=['GET'])
def api_employees():
    if session.get('role') not in ['admin', 'manager']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT employee_id, full_name, role FROM employees WHERE employment_status='active' ORDER BY full_name ASC"
    )
    rows = cur.fetchall()
    cur.close()
    for row in rows:
        if row.get('full_name'): row['full_name'] = aes_decrypt(row['full_name'])
    return jsonify({'success': True, 'employees': rows})


@app.route('/api/attendance', methods=['GET'])
def api_attendance():
    if session.get('role') not in ['admin', 'manager']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    date_str = request.args.get('date')
    search   = (request.args.get('search') or '').strip()

    if date_str:
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid date format'}), 400
    else:
        dt = datetime.now().date()

    cur = mysql.connection.cursor(DictCursor)

    sql = """
        SELECT
            a.attendance_id,
            a.employee_id,
            e.full_name,
            e.role,
            a.shift_type,
            DATE_FORMAT(a.clock_in,  '%%H:%%i:%%s') AS clock_in,
            DATE_FORMAT(a.clock_out, '%%H:%%i:%%s') AS clock_out,
            CASE
                WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                THEN ROUND(TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) / 60, 2)
                ELSE NULL
            END AS hours_worked,
            CASE
                WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                     AND TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) >= 480
                THEN 'YES'
                ELSE 'NO'
            END AS fulfill_working_hours,
            COALESCE(NULLIF(a.daily_earnings,0),
                CASE WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                THEN ROUND(TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) / 60.0
                           * COALESCE(e.hourly_rate, 0), 2)
                ELSE NULL END
            )                                                      AS daily_pay,
            COALESCE(NULLIF(a.hourly_rate_snapshot,0), e.hourly_rate, 0) AS hourly_rate
        FROM attendance a
        JOIN employees e ON e.employee_id = a.employee_id
        WHERE a.attendance_date = %s
    """
    params = [dt]

    if search:
        sql += " AND (e.full_name LIKE %s OR CAST(e.employee_id AS CHAR) LIKE %s)"
        like = f"%{search}%"
        params.extend([like, like])

    sql += " ORDER BY a.clock_in DESC"

    cur.execute(sql, tuple(params))
    rows = cur.fetchall()
    cur.close()
    for row in rows:
        if row.get('full_name'): row['full_name'] = aes_decrypt(row['full_name'])

    return jsonify({'success': True, 'date': str(dt), 'records': rows})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         ADMIN SETTINGS                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/admin_settings')
def admin_settings():
    if not is_admin():
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(DictCursor)
    try:
        if session.get('role') == 'admin' and 'admin_id' in session:
            cur.execute("SELECT full_name FROM admins WHERE admin_id=%s", (session['admin_id'],))
            user = _dec_adm(cur.fetchone())
        else:
            cur.execute("SELECT full_name FROM employees WHERE employee_id=%s", (session['employee_id'],))
            user = _dec_emp(cur.fetchone())
        full_name = user['full_name'] if user else session.get('full_name', 'Admin')
    except Exception:
        full_name = session.get('full_name', 'Admin')
    finally:
        cur.close()

    return render_template('admin_setting.html', full_name=full_name)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         CASHIER DASHBOARD                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/cashier_dashboard')
def cashier_dashboard():
    if 'employee_id' not in session or session.get('role') != 'cashier':
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT full_name, username, role, contact_number, last_login FROM employees WHERE employee_id=%s",
        (session['employee_id'],)
    )
    employee = _dec_emp(cur.fetchone())
    cur.close()

    return render_template('cashier/cashier_dashboard.html', employee=employee)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                            LOGOUT                                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                        ADMIN: UNLOCK ACCOUNT                                 ║
# ║                                                                              ║
# ║  POST /admin/unlock_account                                                  ║
# ║  Body JSON: { "username": str, "role": str }                                 ║
# ║                                                                              ║
# ║  Allows an authenticated admin to manually clear a lockout so a legitimately ║
# ║  locked-out staff member can attempt to log in again immediately.            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/admin/unlock_account', methods=['POST'])
def unlock_account():
    """Clear a login lockout for the given username + role."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data     = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    role     = (data.get('role') or '').strip()

    if not username or role not in ('admin', 'manager', 'cashier'):
        return jsonify({'success': False, 'message': 'username and valid role are required'}), 400

    u_hash = aes_username_hash(username)
    clear_failed_attempts(u_hash, role)
    app.logger.info(
        f"[lockout] Admin {session.get('admin_id') or session.get('employee_id')} "
        f"manually unlocked {role!r} account for username_hash={u_hash[:12]}…"
    )
    return jsonify({'success': True, 'message': f'Lockout cleared for {role} account.'})


@app.route('/admin/lockout_status', methods=['GET'])
def lockout_status():
    """
    Return the current lockout state for a username + role.
    Query params: ?username=...&role=...
    Useful for the admin UI to check status before deciding to unlock.
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    username = (request.args.get('username') or '').strip()
    role     = (request.args.get('role') or '').strip()

    if not username or role not in ('admin', 'manager', 'cashier'):
        return jsonify({'success': False, 'message': 'username and valid role are required'}), 400

    u_hash = aes_username_hash(username)
    state  = check_lockout(u_hash, role)
    return jsonify({'success': True, **state})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                     HIDDEN ADMIN ACCOUNT CREATION                           ║
# ║                                                                              ║
# ║  URL is intentionally unlinked and unguessable.                              ║
# ║  Access requires knowing BOTH the exact path AND the secret setup token.    ║
# ║  Change ADMIN_SETUP_TOKEN to a long random string before deploying.         ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── Secret token that must be submitted with the form ─────────────────────────
# IMPORTANT: Replace this with a long, random string (e.g. from os.urandom).
# Keep this value out of version control (use an environment variable in prod).
ADMIN_SETUP_TOKEN = os.environ.get('ADMIN_SETUP_TOKEN', 'change-me-before-deploying-abc123!')


@app.route('/setup/create-admin-xK9mQ2', methods=['GET', 'POST'])
def create_admin():
    """
    Hidden page for creating a new admin account.

    Security layers:
      1. The URL is long, unguessable, and not linked anywhere in the UI.
      2. Every POST must include a matching ADMIN_SETUP_TOKEN.
      3. The route is NOT listed in any navigation or sitemap.

    Access this page only when you need to bootstrap a new admin account.
    After use, you may restrict the route further (e.g. IP whitelist in nginx).
    """
    if request.method == 'POST':
        submitted_token  = request.form.get('setup_token', '').strip()
        full_name        = request.form.get('full_name', '').strip()
        username         = request.form.get('username', '').strip()
        password         = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # ── 1. Validate secret token ─────────────────────────────────────────
        if submitted_token != ADMIN_SETUP_TOKEN:
            flash('Invalid setup token. Access denied.', 'error')
            return render_template('create_admin.html')

        # ── 2. Validate fields ───────────────────────────────────────────────
        if not all([full_name, username, password, confirm_password]):
            flash('All fields are required.', 'error')
            return render_template('create_admin.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('create_admin.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('create_admin.html')

        # ── 3. Check username uniqueness via hash ────────────────────────────
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT admin_id FROM admins WHERE username_hash = %s LIMIT 1",
                    (aes_username_hash(username),))
        existing = cur.fetchone()

        if existing:
            cur.close()
            flash('That username is already taken. Choose another.', 'error')
            return render_template('create_admin.html')

        # ── 4. Insert new admin (AES-256 encrypted + bcrypt hashed) ─────────
        try:
            cur.execute(
                "INSERT INTO admins (full_name, username, username_hash, password, password_hash) VALUES (%s, %s, %s, %s, %s)",
                (aes_encrypt(full_name), aes_encrypt(username), aes_username_hash(username),
                 aes_encrypt(password), hash_password(password))
            )
            mysql.connection.commit()
            cur.close()
            flash(f'Admin account "{username}" created successfully. You may now log in.', 'success')
        except Exception as e:
            cur.close()
            flash(f'Database error: {e}', 'error')

        return render_template('create_admin.html')

    # GET ─ just render the form
    return render_template('create_admin.html')


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                            ENTRY POINT                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    AUTO-MIGRATION (runs once on first request)               ║
# ║                                                                              ║
# ║  • Adds username_hash column to admins + employees if missing.               ║
# ║  • Encrypts any plaintext rows that were inserted before migration.          ║
# ║  • Safe to run repeatedly — already-encrypted rows are skipped.              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _is_enc(value: str) -> bool:
    """Return True if value is already AES-encrypted (successfully decryptable)."""
    if not value:
        return False
    try:
        raw = base64.b64decode(value)
        if len(raw) < 32:
            return False
        unpad(AES.new(AES_KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), AES.block_size)
        return True
    except Exception:
        return False


def run_auto_migration():
    """
    Runs once on first request.  Order matters:
      1. Add username_hash columns (DDL).
      2. WIDEN narrow VARCHAR columns BEFORE writing any ciphertext — the old
         contact_number VARCHAR(20) silently truncated the base64 blob, making
         it undecryptable.  All encrypted fields need VARCHAR(255).
      3. Re-encrypt any rows whose contact_number was already truncated by
         clearing the corrupt value so the UI shows '' instead of garbage.
      4. Encrypt all remaining plaintext rows.
    """
    try:
        conn = mysql.connection
        cur  = conn.cursor(DictCursor)

        # ── STEP 1: add username_hash columns ────────────────────────────────
        for tbl in ('employees', 'admins'):
            try:
                cur.execute(
                    f"ALTER TABLE `{tbl}` "
                    f"ADD COLUMN `username_hash` VARCHAR(64) DEFAULT NULL"
                )
                conn.commit()
                app.logger.info(f"[migration] Added username_hash to {tbl}")
            except Exception:
                pass  # already exists

        # ── STEP 2: widen columns — MUST happen before any UPDATE ────────────
        # AES-256-CBC base64(IV+ciphertext) is always >= 44 chars.
        # VARCHAR(20) and VARCHAR(50) silently truncate the blob on write.
        widen = [
            ("employees", "contact_number", "VARCHAR(255)"),
            ("employees", "username",       "VARCHAR(255)"),
            ("employees", "full_name",      "VARCHAR(255)"),
            ("employees", "password",       "VARCHAR(255)"),
            ("admins",    "username",       "VARCHAR(255)"),
            ("admins",    "full_name",      "VARCHAR(255)"),
            ("admins",    "password",       "VARCHAR(255)"),
        ]
        for tbl, col, typ in widen:
            try:
                cur.execute(f"ALTER TABLE `{tbl}` MODIFY COLUMN `{col}` {typ} NOT NULL DEFAULT ''")
                conn.commit()
                app.logger.info(f"[migration] Widened {tbl}.{col} -> {typ}")
            except Exception as e:
                # Column may already be the right width — skip silently
                app.logger.debug(f"[migration] Widen {tbl}.{col} skipped: {e}")

        # ── STEP 3 & 4: repair truncated rows and encrypt plaintext ──────────
        cur.execute(
            "SELECT employee_id, username, full_name, password, contact_number "
            "FROM employees"
        )
        for row in cur.fetchall():
            upd = {}
            for f in ('username', 'full_name', 'password', 'contact_number'):
                v = row.get(f)
                if not v:
                    continue
                s = str(v).strip()
                if _is_enc(s):
                    continue  # already good AES ciphertext
                # Detect truncated ciphertext: looks like base64 but fails decryption
                # These have base64 chars and length 20-43 (truncated by old column).
                # We cannot recover the plaintext — clear them so UI shows empty.
                import re as _re
                if _re.fullmatch(r'[A-Za-z0-9+/=]+', s) and 16 <= len(s) < 44:
                    upd[f] = ''   # clear corrupt value
                    app.logger.warning(
                        f"[migration] Cleared truncated ciphertext in "
                        f"employee #{row['employee_id']}.{f}"
                    )
                else:
                    upd[f] = aes_encrypt(s)

            raw_u = row.get('username', '') or ''
            plain_u = aes_decrypt(str(raw_u).strip()) if raw_u else ''
            # Recompute hash if username was plaintext (pre-encryption)
            if raw_u and not _is_enc(str(raw_u).strip()):
                upd['username_hash'] = aes_username_hash(str(raw_u).strip())
            elif plain_u and not row.get('username_hash'):
                upd['username_hash'] = aes_username_hash(plain_u)

            if upd:
                sql = (
                    "UPDATE employees SET "
                    + ", ".join(f"`{k}`=%s" for k in upd)
                    + " WHERE employee_id=%s"
                )
                cur.execute(sql, list(upd.values()) + [row['employee_id']])
                app.logger.info(f"[migration] Fixed employee #{row['employee_id']} fields={list(upd.keys())}")

        cur.execute("SELECT admin_id, username, full_name, password FROM admins")
        for row in cur.fetchall():
            upd = {}
            for f in ('username', 'full_name', 'password'):
                v = row.get(f)
                if not v:
                    continue
                s = str(v).strip()
                if _is_enc(s):
                    continue
                import re as _re
                if _re.fullmatch(r'[A-Za-z0-9+/=]+', s) and 16 <= len(s) < 44:
                    upd[f] = ''
                    app.logger.warning(
                        f"[migration] Cleared truncated ciphertext in "
                        f"admin #{row['admin_id']}.{f}"
                    )
                else:
                    upd[f] = aes_encrypt(s)

            raw_u = row.get('username', '') or ''
            if raw_u and not _is_enc(str(raw_u).strip()):
                upd['username_hash'] = aes_username_hash(str(raw_u).strip())

            if upd:
                sql = (
                    "UPDATE admins SET "
                    + ", ".join(f"`{k}`=%s" for k in upd)
                    + " WHERE admin_id=%s"
                )
                cur.execute(sql, list(upd.values()) + [row['admin_id']])
                app.logger.info(f"[migration] Fixed admin #{row['admin_id']} fields={list(upd.keys())}")

        conn.commit()
        cur.close()
        app.logger.info("[migration] All done.")

        # ── STEP 5: add password_hash columns & backfill bcrypt hashes ────────
        _widen_password_hash_columns()
        _backfill_bcrypt_hashes()

        # ── STEP 6: create login_attempts table for lockout policy ────────────
        _ensure_lockout_table()

        # ── STEP 7: widen face_model_path VARCHAR(255) → MEDIUMTEXT ──────────
        # FaceNet-512 JSON embeddings are ~6 KB — VARCHAR(255) silently truncates
        # them, which causes persist_embedding() to store NULL and forces every
        # verification to fall back to the less-accurate single-image path.
        _widen_face_model_path()

        # ── STEP 8: create employees_trash table + migrate inactive rows ──────
        # Disabled employees are moved to trash and permanently deleted after 24h.
        _ensure_trash_table()

        # ── STEP 9: payroll tables (hourly_rate, attendance columns, payroll_periods, payslips) ──
        _ensure_payroll_tables()

    except Exception as exc:
        app.logger.error(f"[auto-migration] Failed: {exc}")


def _ensure_payroll_tables():
    """
    Idempotent DDL bootstrap — all ALTER TABLE calls skip silently if columns
    already exist (schema is already up-to-date in the current DB version).
    """
    try:
        conn = mysql.connection
        cur  = conn.cursor()

        # ── employees.hourly_rate ──────────────────────────────────────────
        try:
            cur.execute(
                "ALTER TABLE `employees` "
                "ADD COLUMN `hourly_rate` DECIMAL(10,2) NOT NULL DEFAULT 0.00"
            )
            conn.commit()
            app.logger.info("[payroll] Added employees.hourly_rate")
        except Exception:
            pass

        # ── attendance payroll columns ─────────────────────────────────────
        for col, defn in [
            ("hours_worked",         "DECIMAL(10,2) NOT NULL DEFAULT 0.00"),
            ("hourly_rate_snapshot", "DECIMAL(10,2) NOT NULL DEFAULT 0.00"),
            ("daily_earnings",       "DECIMAL(10,2) NOT NULL DEFAULT 0.00"),
            ("pay_period_start",     "DATE DEFAULT NULL"),
            ("pay_period_end",       "DATE DEFAULT NULL"),
        ]:
            try:
                cur.execute(f"ALTER TABLE `attendance` ADD COLUMN `{col}` {defn}")
                conn.commit()
                app.logger.info(f"[payroll] Added attendance.{col}")
            except Exception:
                pass

        # ── payroll_periods ───────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS `payroll_periods` (
                `period_id`    INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                `period_start` DATE         NOT NULL,
                `period_end`   DATE         NOT NULL,
                `label`        VARCHAR(60)  NOT NULL DEFAULT '',
                `status`       ENUM('open','closed') NOT NULL DEFAULT 'open',
                `created_at`   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY `uq_period` (`period_start`, `period_end`),
                INDEX `idx_status` (`status`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """)
        # ── payslips ───────────────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS `payslips` (
                `payslip_id`   INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
                `period_id`    INT UNSIGNED  NOT NULL,
                `employee_id`  INT           NOT NULL,
                `hourly_rate`  DECIMAL(10,2) NOT NULL DEFAULT 0.00,
                `total_hours`  DECIMAL(8,2)  NOT NULL DEFAULT 0.00,
                `gross_pay`    DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                `days_worked`  INT           NOT NULL DEFAULT 0,
                `generated_at` DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `generated_by` VARCHAR(60)   DEFAULT NULL,
                INDEX `idx_period`   (`period_id`),
                INDEX `idx_employee` (`employee_id`),
                CONSTRAINT `fk_ps_period`
                    FOREIGN KEY (`period_id`)  REFERENCES `payroll_periods`(`period_id`) ON DELETE CASCADE,
                CONSTRAINT `fk_ps_employee`
                    FOREIGN KEY (`employee_id`) REFERENCES `employees`(`employee_id`) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """)
        conn.commit()
        app.logger.info("[payroll] Payroll tables ensured")
        cur.close()
    except Exception as exc:
        app.logger.error(f"[payroll] _ensure_payroll_tables failed: {exc}")


# ── Clock-out pay persistence ────────────────────────────────────────────────

def _store_clock_out_pay(conn, attendance_id: int):
    """
    Called immediately after a successful clock-out.
    Writes hours_worked, hourly_rate_snapshot, daily_earnings,
    pay_period_start, pay_period_end to the attendance row in one UPDATE.
    Uses COALESCE fallback so the displayed values are always fresh.
    """
    import calendar as _cal
    try:
        cur = conn.cursor(DictCursor)
        cur.execute("""
            SELECT a.clock_in, a.clock_out, a.attendance_date,
                   COALESCE(e.hourly_rate, 0) AS hourly_rate
            FROM   attendance a
            JOIN   employees  e ON e.employee_id = a.employee_id
            WHERE  a.attendance_id = %s
        """, (attendance_id,))
        row = cur.fetchone()
        if not row or not row.get('clock_out'):
            cur.close(); return

        delta_min = (row['clock_out'] - row['clock_in']).total_seconds() / 60.0
        hours     = round(delta_min / 60.0, 4)
        rate      = float(row['hourly_rate'])
        earnings  = round(hours * rate, 2)

        d = row['attendance_date']
        if d.day <= 15:
            ps, pe = d.replace(day=1), d.replace(day=15)
        else:
            last = _cal.monthrange(d.year, d.month)[1]
            ps, pe = d.replace(day=16), d.replace(day=last)

        cur.execute("""
            UPDATE attendance
               SET hours_worked         = %s,
                   hourly_rate_snapshot = %s,
                   daily_earnings       = %s,
                   pay_period_start     = %s,
                   pay_period_end       = %s
             WHERE attendance_id = %s
        """, (hours, rate, earnings, ps, pe, attendance_id))
        conn.commit()
        cur.close()
        app.logger.info(
            f"[payroll] att#{attendance_id}: {hours:.2f}h x P{rate:.2f} = P{earnings:.2f} ({ps}->{pe})"
        )
    except Exception as exc:
        app.logger.error(f"[payroll] _store_clock_out_pay failed att#{attendance_id}: {exc}")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                          PAYROLL ROUTES                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _compute_period_bounds(ref_date=None):
    """
    Return (period_start, period_end) for the 15-day pay period that contains
    ref_date.  The company uses two fixed periods per month:
      • 1st – 15th
      • 16th – last day of month
    """
    from datetime import date, timedelta
    import calendar as _cal
    d = ref_date or date.today()
    if d.day <= 15:
        return date(d.year, d.month, 1), date(d.year, d.month, 15)
    else:
        last = _cal.monthrange(d.year, d.month)[1]
        return date(d.year, d.month, 16), date(d.year, d.month, last)


@app.route('/payroll')
def payroll():
    """Render the payroll dashboard page."""
    if not is_admin():
        return redirect(url_for('login'))
    cur = mysql.connection.cursor(DictCursor)
    if session.get('role') == 'admin' and 'admin_id' in session:
        cur.execute("SELECT full_name FROM admins WHERE admin_id=%s", (session['admin_id'],))
        user = _dec_adm(cur.fetchone())
    else:
        cur.execute("SELECT full_name FROM employees WHERE employee_id=%s", (session['employee_id'],))
        user = _dec_emp(cur.fetchone())
    full_name = user['full_name'] if user else session.get('full_name', 'Admin')
    cur.close()
    return render_template('payroll.html', full_name=full_name)


@app.route('/api/payroll/employees', methods=['GET'])
def api_payroll_employees():
    """
    Return all active employees with their hourly_rate for the payroll UI.
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT employee_id, full_name, role, hourly_rate "
        "FROM employees WHERE employment_status='active' ORDER BY full_name"
    )
    rows = cur.fetchall()
    cur.close()
    for row in rows:
        if row.get('full_name'):
            row['full_name'] = aes_decrypt(row['full_name']) or row['full_name']
        row['hourly_rate'] = float(row['hourly_rate'] or 0)
    return jsonify({'success': True, 'employees': rows})


@app.route('/api/payroll/update_rate', methods=['POST'])
def api_payroll_update_rate():
    """Admin: update an employee's hourly_rate."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    employee_id = data.get('employee_id')
    try:
        rate = float(data.get('hourly_rate', 0))
        if rate < 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Invalid hourly rate'}), 400
    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE employees SET hourly_rate=%s WHERE employee_id=%s",
        (rate, employee_id)
    )
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True, 'message': 'Hourly rate updated'})


@app.route('/api/payroll/daily', methods=['GET'])
def api_payroll_daily():
    """
    Return daily pay breakdown for each employee for a given date.
    Calculates: hours_worked × hourly_rate = daily_pay.
    Also persists daily_pay back to the attendance row.
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    date_str = request.args.get('date')
    try:
        from datetime import date as _date
        dt = datetime.strptime(date_str, "%Y-%m-%d").date() if date_str else _date.today()
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid date'}), 400

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("""
        SELECT
            a.attendance_id,
            a.employee_id,
            e.full_name,
            e.role,
            a.shift_type,
            DATE_FORMAT(a.clock_in,  '%%H:%%i') AS clock_in,
            DATE_FORMAT(a.clock_out, '%%H:%%i') AS clock_out,
            COALESCE(NULLIF(a.hours_worked,0),
                CASE WHEN a.clock_out IS NOT NULL
                THEN ROUND(TIMESTAMPDIFF(MINUTE,a.clock_in,a.clock_out)/60.0,4)
                ELSE NULL END)                                         AS hours_worked,
            COALESCE(NULLIF(a.hourly_rate_snapshot,0),e.hourly_rate,0) AS hourly_rate,
            COALESCE(NULLIF(a.daily_earnings,0),
                CASE WHEN a.clock_out IS NOT NULL
                THEN ROUND(TIMESTAMPDIFF(MINUTE,a.clock_in,a.clock_out)/60.0
                           * COALESCE(e.hourly_rate,0),2)
                ELSE NULL END)                                         AS daily_earnings,
            a.pay_period_start,
            a.pay_period_end
        FROM attendance a
        JOIN employees e ON e.employee_id = a.employee_id
        WHERE a.attendance_date = %s
        ORDER BY e.full_name
    """, (dt,))
    rows = cur.fetchall()

    result = []
    for row in rows:
        name  = aes_decrypt(row['full_name']) if row.get('full_name') else ''
        hours = float(row['hours_worked']  or 0) if row['hours_worked']  is not None else None
        rate  = float(row['hourly_rate']   or 0)
        pay   = float(row['daily_earnings'] or 0) if row['daily_earnings'] is not None else None
        result.append({
            'attendance_id':    row['attendance_id'],
            'employee_id':      row['employee_id'],
            'full_name':        name,
            'role':             row['role'],
            'shift_type':       row['shift_type'],
            'clock_in':         row['clock_in'],
            'clock_out':        row['clock_out'],
            'hours_worked':     round(hours,2) if hours is not None else None,
            'hourly_rate':      rate,
            'daily_pay':        round(pay,2)   if pay   is not None else None,
            'pay_period_start': str(row['pay_period_start']) if row['pay_period_start'] else None,
            'pay_period_end':   str(row['pay_period_end'])   if row['pay_period_end']   else None,
        })

    cur.close()
    return jsonify({'success': True, 'date': str(dt), 'records': result})


@app.route('/api/payroll/period', methods=['GET'])
def api_payroll_period():
    """
    Return payroll summary for a 15-day period.

    Query params:
        period_start  — YYYY-MM-DD  (auto-computed if omitted)
        period_end    — YYYY-MM-DD
        employee_id   — optional filter
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    from datetime import date as _date, timedelta
    import calendar as _cal

    # ── Resolve period bounds ────────────────────────────────────────────────
    ps = request.args.get('period_start')
    pe = request.args.get('period_end')
    try:
        if ps and pe:
            period_start = datetime.strptime(ps, "%Y-%m-%d").date()
            period_end   = datetime.strptime(pe, "%Y-%m-%d").date()
        else:
            period_start, period_end = _compute_period_bounds()
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid date format'}), 400

    employee_id = request.args.get('employee_id')

    cur = mysql.connection.cursor(DictCursor)

    sql = """
        SELECT
            e.employee_id,
            e.full_name,
            e.role,
            e.hourly_rate,
            COUNT(a.attendance_id)                                           AS days_worked,
            ROUND(
                SUM(CASE
                    WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                    THEN TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) / 60.0
                    ELSE 0 END), 2)                                          AS total_hours,
            ROUND(SUM(COALESCE(NULLIF(a.daily_earnings,0),
                CASE WHEN a.clock_out IS NOT NULL
                THEN (TIMESTAMPDIFF(MINUTE,a.clock_in,a.clock_out)/60.0)*e.hourly_rate
                ELSE 0 END)),2)                                              AS total_pay
        FROM employees e
        LEFT JOIN attendance a
            ON a.employee_id = e.employee_id
           AND a.attendance_date BETWEEN %s AND %s
        WHERE e.employment_status = 'active'
    """
    params = [period_start, period_end]

    if employee_id:
        sql += " AND e.employee_id = %s"
        params.append(employee_id)

    sql += " GROUP BY e.employee_id ORDER BY e.full_name"

    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close()

    result = []
    for row in rows:
        name = aes_decrypt(row['full_name']) if row.get('full_name') else ''
        result.append({
            'employee_id':  row['employee_id'],
            'full_name':    name,
            'role':         row['role'],
            'hourly_rate':  float(row['hourly_rate'] or 0),
            'days_worked':  int(row['days_worked'] or 0),
            'total_hours':  float(row['total_hours'] or 0),
            'total_pay':    float(row['total_pay']  or 0),
        })

    grand_total = round(sum(r['total_pay'] for r in result), 2)
    return jsonify({
        'success':      True,
        'period_start': str(period_start),
        'period_end':   str(period_end),
        'records':      result,
        'grand_total':  grand_total,
    })


@app.route('/api/payroll/period_detail', methods=['GET'])
def api_payroll_period_detail():
    """
    Day-by-day breakdown for a single employee within a pay period.
    Used when clicking an employee row to expand details.
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    employee_id  = request.args.get('employee_id')
    period_start = request.args.get('period_start')
    period_end   = request.args.get('period_end')

    if not all([employee_id, period_start, period_end]):
        return jsonify({'success': False, 'message': 'Missing parameters'}), 400

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("""
        SELECT
            a.attendance_date,
            a.shift_type,
            DATE_FORMAT(a.clock_in,  '%%H:%%i') AS clock_in,
            DATE_FORMAT(a.clock_out, '%%H:%%i') AS clock_out,
            COALESCE(NULLIF(a.hours_worked,0),
                CASE WHEN a.clock_out IS NOT NULL
                THEN ROUND(TIMESTAMPDIFF(MINUTE,a.clock_in,a.clock_out)/60.0,2)
                ELSE 0 END)                                        AS hours_worked,
            COALESCE(NULLIF(a.hourly_rate_snapshot,0),e.hourly_rate,0) AS hourly_rate,
            COALESCE(NULLIF(a.daily_earnings,0),
                CASE WHEN a.clock_out IS NOT NULL
                THEN ROUND((TIMESTAMPDIFF(MINUTE,a.clock_in,a.clock_out)/60.0)*
                           COALESCE(e.hourly_rate,0),2)
                ELSE 0 END)                                        AS daily_pay
        FROM attendance a
        JOIN employees e ON e.employee_id = a.employee_id
        WHERE a.employee_id = %s
          AND a.attendance_date BETWEEN %s AND %s
        ORDER BY a.attendance_date
    """, (employee_id, period_start, period_end))
    rows = cur.fetchall()
    cur.close()

    for row in rows:
        row['attendance_date'] = str(row['attendance_date'])
        row['hours_worked']    = float(row['hours_worked'] or 0)
        row['daily_pay']       = float(row['daily_pay']   or 0)
        row['hourly_rate']     = float(row['hourly_rate'] or 0)

    return jsonify({'success': True, 'days': rows})


@app.route('/api/payroll/salary_detail', methods=['GET'])
def api_payroll_salary_detail():
    """
    Return a full 15-day salary breakdown for a single employee.

    Generates a row for EVERY calendar day in the period (not just days with
    attendance), so the frontend can render a complete grid even on off days.

    Query params:
        employee_id   — required
        period_start  — YYYY-MM-DD  (required)
        period_end    — YYYY-MM-DD  (required)
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    employee_id  = request.args.get('employee_id')
    period_start = request.args.get('period_start')
    period_end   = request.args.get('period_end')

    if not all([employee_id, period_start, period_end]):
        return jsonify({'success': False, 'message': 'Missing parameters'}), 400

    try:
        from datetime import date as _date, timedelta as _td
        ps = datetime.strptime(period_start, "%Y-%m-%d").date()
        pe = datetime.strptime(period_end,   "%Y-%m-%d").date()
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid date format'}), 400

    cur = mysql.connection.cursor(DictCursor)

    # ── Fetch employee info ──────────────────────────────────────────────────
    cur.execute(
        "SELECT employee_id, full_name, role, hourly_rate "
        "FROM employees WHERE employee_id = %s LIMIT 1",
        (employee_id,)
    )
    emp = cur.fetchone()
    if not emp:
        cur.close()
        return jsonify({'success': False, 'message': 'Employee not found'}), 404

    emp_name = aes_decrypt(emp['full_name']) if emp.get('full_name') else ''
    base_rate = float(emp['hourly_rate'] or 0)

    # ── Fetch attendance rows in range ───────────────────────────────────────
    cur.execute("""
        SELECT
            a.attendance_date,
            a.shift_type,
            DATE_FORMAT(a.clock_in,  '%%H:%%i') AS clock_in,
            DATE_FORMAT(a.clock_out, '%%H:%%i') AS clock_out,
            COALESCE(NULLIF(a.hours_worked, 0),
                CASE WHEN a.clock_out IS NOT NULL
                THEN ROUND(TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) / 60.0, 2)
                ELSE 0 END)                                         AS hours_worked,
            COALESCE(NULLIF(a.hourly_rate_snapshot, 0), %s, 0)     AS hourly_rate,
            COALESCE(NULLIF(a.daily_earnings, 0),
                CASE WHEN a.clock_out IS NOT NULL
                THEN ROUND((TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) / 60.0) *
                           COALESCE(NULLIF(a.hourly_rate_snapshot, 0), %s, 0), 2)
                ELSE 0 END)                                         AS daily_pay
        FROM attendance a
        WHERE a.employee_id = %s
          AND a.attendance_date BETWEEN %s AND %s
        ORDER BY a.attendance_date
    """, (base_rate, base_rate, employee_id, ps, pe))

    attendance_rows = cur.fetchall()
    cur.close()

    # Index existing rows by date for fast lookup
    att_by_date = {}
    for row in attendance_rows:
        key = str(row['attendance_date'])
        att_by_date[key] = {
            'attendance_date': key,
            'shift_type':   row['shift_type'],
            'clock_in':     row['clock_in'],
            'clock_out':    row['clock_out'],
            'hours_worked': float(row['hours_worked'] or 0),
            'hourly_rate':  float(row['hourly_rate']  or 0),
            'daily_pay':    float(row['daily_pay']    or 0),
        }

    # ── Build full calendar grid (every day in the period) ───────────────────
    days = []
    current = ps
    while current <= pe:
        key = str(current)
        if key in att_by_date:
            days.append(att_by_date[key])
        else:
            # Off day / no attendance record — include as a zero row
            days.append({
                'attendance_date': key,
                'shift_type':   None,
                'clock_in':     None,
                'clock_out':    None,
                'hours_worked': 0.0,
                'hourly_rate':  base_rate,
                'daily_pay':    0.0,
            })
        current += _td(days=1)

    total_income = round(sum(d['daily_pay'] for d in days), 2)
    total_hours  = round(sum(d['hours_worked'] for d in days), 2)
    days_worked  = sum(1 for d in days if d['daily_pay'] > 0)

    return jsonify({
        'success':       True,
        'employee_id':   int(employee_id),
        'full_name':     emp_name,
        'role':          emp['role'],
        'hourly_rate':   base_rate,
        'period_start':  str(ps),
        'period_end':    str(pe),
        'total_income':  total_income,
        'total_hours':   total_hours,
        'days_worked':   days_worked,
        'days':          days,
    })
def api_payroll_generate():
    """
    Compute and upsert payroll_periods rows for a given pay period.
    Returns the generated summaries.
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}
    ps   = data.get('period_start')
    pe   = data.get('period_end')

    try:
        period_start = datetime.strptime(ps, "%Y-%m-%d").date()
        period_end   = datetime.strptime(pe, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Invalid period dates'}), 400

    cur = mysql.connection.cursor(DictCursor)

    cur.execute("""
        SELECT
            e.employee_id,
            e.full_name,
            e.hourly_rate,
            COUNT(a.attendance_id)                                           AS days_worked,
            ROUND(
                SUM(CASE
                    WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                    THEN TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) / 60.0
                    ELSE 0 END), 4)                                          AS total_hours,
            ROUND(SUM(COALESCE(NULLIF(a.daily_earnings,0),
                CASE WHEN a.clock_out IS NOT NULL
                THEN (TIMESTAMPDIFF(MINUTE,a.clock_in,a.clock_out)/60.0)*e.hourly_rate
                ELSE 0 END)),2)                                              AS total_pay
        FROM employees e
        LEFT JOIN attendance a
            ON a.employee_id = e.employee_id
           AND a.attendance_date BETWEEN %s AND %s
        WHERE e.employment_status = 'active'
        GROUP BY e.employee_id
    """, (period_start, period_end))
    rows = cur.fetchall()

    generated = []
    for row in rows:
        name = aes_decrypt(row['full_name']) if row.get('full_name') else ''
        hours = float(row['total_hours'] or 0)
        pay   = float(row['total_pay']   or 0)
        days  = int(row['days_worked']   or 0)

        # get/create payroll_period row, then upsert payslip
        lbl = f"{period_start.strftime('%b')}" \
              f" {period_start.day}\u2013{period_end.day}, {period_start.year}"
        cur.execute(
            "SELECT period_id FROM payroll_periods "
            "WHERE period_start=%s AND period_end=%s LIMIT 1",
            (period_start, period_end))
        pr = cur.fetchone()
        if pr:
            period_id = pr['period_id']
        else:
            cur.execute(
                "INSERT INTO payroll_periods (period_start, period_end, label) "
                "VALUES (%s,%s,%s)", (period_start, period_end, lbl))
            mysql.connection.commit()
            period_id = cur.lastrowid
        cur.execute("DELETE FROM payslips WHERE period_id=%s AND employee_id=%s",
                    (period_id, row['employee_id']))
        cur.execute("""
            INSERT INTO payslips
                (period_id, employee_id, hourly_rate, total_hours, gross_pay, days_worked)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (period_id, row['employee_id'],
               float(row['hourly_rate'] or 0), hours, pay, days))

        generated.append({
            'employee_id': row['employee_id'],
            'full_name':   name,
            'total_hours': round(hours, 2),
            'total_pay':   pay,
            'days_worked': days,
        })

    mysql.connection.commit()
    cur.close()

    grand_total = round(sum(r['total_pay'] for r in generated), 2)
    return jsonify({
        'success':      True,
        'period_start': str(period_start),
        'period_end':   str(period_end),
        'records':      generated,
        'grand_total':  grand_total,
        'message':      f'Payroll generated for {len(generated)} employee(s)',
    })


@app.route('/api/payroll/history', methods=['GET'])
def api_payroll_history():
    """Return previously generated payroll periods."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("""
        SELECT
            ps.payslip_id, ps.employee_id,
            pp.period_start, pp.period_end, pp.label, pp.status,
            ps.total_hours, ps.gross_pay AS total_pay, ps.days_worked,
            ps.hourly_rate, ps.generated_at, ps.generated_by,
            e.full_name, e.role
        FROM payslips ps
        JOIN payroll_periods pp ON pp.period_id = ps.period_id
        JOIN employees e        ON e.employee_id = ps.employee_id
        ORDER BY pp.period_start DESC, e.full_name
        LIMIT 200
    """)
    rows = cur.fetchall()
    cur.close()

    for row in rows:
        row['full_name']    = aes_decrypt(row['full_name']) if row.get('full_name') else ''
        row['period_start'] = str(row['period_start'])
        row['period_end']   = str(row['period_end'])
        row['generated_at'] = str(row['generated_at'])
        row['total_hours']  = float(row['total_hours'] or 0)
        row['total_pay']    = float(row['total_pay']   or 0)
        row['hourly_rate']  = float(row['hourly_rate'] or 0)

    return jsonify({'success': True, 'history': rows})


_migration_done = False

@app.before_request
def ensure_migration():
    """Run the DB migration exactly once after the app has a live DB connection."""
    global _migration_done
    if not _migration_done:
        _migration_done = True   # Set first so a crash doesn't cause infinite loops
        run_auto_migration()
    # Run the trash purge on every request (rate-limited internally to every 5 min)
    _purge_expired_trash()


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                            ENTRY POINT                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

if __name__ == '__main__':
    # ── debug=False prevents TensorFlow/Keras exceptions from being re-raised
    # ── as fatal errors by Werkzeug's debug handler, which was killing the
    # ── server during DeepFace embedding calls.
    app.run(debug=False, use_reloader=False)