from flask import (
    Flask,
    render_template,
    request,
    redirect,
    flash,
    session,
    url_for,
    jsonify,
)
from flask_mysqldb import MySQL
from MySQLdb.cursors import DictCursor
from deepface import DeepFace
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64, cv2, os, numpy as np, time, hashlib, bcrypt, json, secrets
import smtplib, threading, csv, io
from flask import Response
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "SecretKey")

_AES_RAW = os.environ.get("AES_SECRET_KEY", "change-this-aes-key-before-deploy!")
AES_KEY = hashlib.sha256(_AES_RAW.encode()).digest()  # 32 bytes


def aes_encrypt(plaintext: str) -> str:
    """AES-256-CBC encrypt → base64(IV + ciphertext)."""
    if not plaintext:
        return plaintext
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode("utf-8")


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
        iv = raw[:16]
        ct = raw[16:]
        return unpad(
            AES.new(AES_KEY, AES.MODE_CBC, iv).decrypt(ct), AES.block_size
        ).decode("utf-8")
    except Exception:
        if len(token) < 44 and "=" not in token:
            return token  # short legacy plaintext
        return ""  # corrupt/truncated ciphertext — return empty, never raw garbage


def aes_username_hash(username: str) -> str:
    """
    Produce a deterministic SHA-256 digest of (AES_KEY + username).
    Used for WHERE username_hash=? lookups — fast and secure with only
    the AES_SECRET_KEY; no separate HMAC key required.
    """
    return hashlib.sha256(
        AES_KEY + username.strip().lower().encode("utf-8")
    ).hexdigest()


BCRYPT_ROUNDS = 12  # work factor — increase to 13+ if hardware allows


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password with bcrypt.  Returns a UTF-8 string."""
    return bcrypt.hashpw(
        plaintext.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)
    ).decode("utf-8")


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
            return bcrypt.checkpw(
                plaintext.encode("utf-8"), stored_hash.encode("utf-8")
            )
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
    ph = (row.get("password_hash") or "").strip()
    if ph:
        return verify_password(plaintext, ph)
    # Legacy fallback: compare against AES-decrypted password
    legacy = (row.get("password") or "").strip()
    return bool(legacy and legacy == plaintext)


def _widen_password_hash_columns():
    """
    Add password_hash VARCHAR(255) column to employees and admins if absent.
    Called once at startup inside run_auto_migration().
    """
    try:
        conn = mysql.connection
        cur = conn.cursor(DictCursor)
        for tbl in ("employees", "admins"):
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
        cur = conn.cursor(DictCursor)

        # ── employees ──────────────────────────────────────────────────────────
        cur.execute(
            "SELECT employee_id, password FROM employees "
            "WHERE (password_hash IS NULL OR password_hash = '') AND password != ''"
        )
        for row in cur.fetchall():
            plaintext = (
                aes_decrypt(str(row["password"]).strip())
                if row.get("password")
                else None
            )
            if plaintext:
                new_hash = hash_password(plaintext)
                cur.execute(
                    "UPDATE employees SET password_hash=%s WHERE employee_id=%s",
                    (new_hash, row["employee_id"]),
                )
                app.logger.info(
                    f"[migration] bcrypt backfill — employee #{row['employee_id']}"
                )

        # ── admins ─────────────────────────────────────────────────────────────
        cur.execute(
            "SELECT admin_id, password FROM admins "
            "WHERE (password_hash IS NULL OR password_hash = '') AND password != ''"
        )
        for row in cur.fetchall():
            plaintext = (
                aes_decrypt(str(row["password"]).strip())
                if row.get("password")
                else None
            )
            if plaintext:
                new_hash = hash_password(plaintext)
                cur.execute(
                    "UPDATE admins SET password_hash=%s WHERE admin_id=%s",
                    (new_hash, row["admin_id"]),
                )
                app.logger.info(
                    f"[migration] bcrypt backfill — admin #{row['admin_id']}"
                )

        conn.commit()
        cur.close()
        app.logger.info("[migration] bcrypt backfill complete")
    except Exception as exc:
        app.logger.error(f"[migration] _backfill_bcrypt_hashes failed: {exc}")


MAX_ATTEMPTS = 5  # lock after this many consecutive failures
LOCKOUT_MINS = 15  # minutes the account stays locked
WARN_AT = 3  # show "X attempts remaining" when failures reach this


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
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS `login_attempts` (
                `attempt_key`   VARCHAR(64)  NOT NULL,
                `fail_count`    INT          NOT NULL DEFAULT 0,
                `locked_until`  DATETIME     DEFAULT NULL,
                `last_attempt`  DATETIME     DEFAULT NULL,
                PRIMARY KEY (`attempt_key`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """
        )
        # ── Face mismatch security log ───────────────────────────────────────
        cur.execute(
            """
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
        """
        )
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
        cur = conn.cursor(DictCursor)

        # Check the current column type
        cur.execute(
            """
            SELECT DATA_TYPE, CHARACTER_MAXIMUM_LENGTH
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME   = 'employees'
              AND COLUMN_NAME  = 'face_model_path'
        """
        )
        col = cur.fetchone()

        if col is None:
            # Column doesn't exist at all — add it as MEDIUMTEXT
            cur.execute(
                "ALTER TABLE `employees` ADD COLUMN `face_model_path` MEDIUMTEXT DEFAULT NULL"
            )
            conn.commit()
            app.logger.info("[migration] face_model_path column added as MEDIUMTEXT")
        elif col["DATA_TYPE"].lower() in ("varchar", "char", "tinytext"):
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
        cur = conn.cursor(DictCursor)

        cur.execute(
            """
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
        """
        )
        conn.commit()
        app.logger.info("[migration] employees_trash table ensured")

        # ── Migrate existing inactive employees into trash ───────────────────
        cur.execute(
            """
            SELECT employee_id, full_name, username, username_hash,
                   password, password_hash, role, contact_number,
                   face_image_path, face_model_path, last_login,
                   created_at, disabled_at
            FROM employees
            WHERE employment_status = 'inactive'
              AND disabled_at IS NOT NULL
              AND employee_id NOT IN (SELECT employee_id FROM employees_trash)
        """
        )
        rows = cur.fetchall()
        migrated = 0
        for row in rows:
            disabled_at = row["disabled_at"] or datetime.now()
            import datetime as _dt

            delete_at = disabled_at + _dt.timedelta(hours=24)
            cur.execute(
                """
                INSERT INTO employees_trash
                    (employee_id, full_name, username, username_hash,
                     password, password_hash, role, contact_number,
                     face_image_path, face_model_path, last_login,
                     created_at, disabled_at, delete_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
                (
                    row["employee_id"],
                    row["full_name"],
                    row["username"],
                    row["username_hash"],
                    row["password"],
                    row["password_hash"],
                    row["role"],
                    row["contact_number"],
                    row["face_image_path"],
                    row["face_model_path"],
                    row["last_login"],
                    row["created_at"],
                    disabled_at,
                    delete_at,
                ),
            )
            migrated += 1
        if migrated:
            conn.commit()
            app.logger.info(
                f"[migration] Moved {migrated} inactive employee(s) to trash"
            )
        cur.close()
    except Exception as exc:
        app.logger.error(f"[migration] _ensure_trash_table failed: {exc}")


# Timestamp of last purge check — avoids hitting DB on every single request
_last_purge_check = None
_PURGE_INTERVAL_SECONDS = 300  # check at most every 5 minutes


def _purge_expired_trash():
    """
    Permanently delete employees whose 24-hour grace period has expired.
    Removes the employee row, the trash row, and the face image file from disk.
    Called lazily on requests, at most every _PURGE_INTERVAL_SECONDS.
    """
    global _last_purge_check
    now = datetime.now()
    if (
        _last_purge_check
        and (now - _last_purge_check).total_seconds() < _PURGE_INTERVAL_SECONDS
    ):
        return
    _last_purge_check = now

    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            """
            SELECT trash_id, employee_id, face_image_path
            FROM employees_trash
            WHERE delete_at <= NOW()
        """
        )
        expired = cur.fetchall()

        for row in expired:
            emp_id = row["employee_id"]

            # Delete face image from disk
            face_path = row.get("face_image_path")
            if face_path:
                full_path = os.path.join("static", face_path)
                try:
                    if os.path.exists(full_path):
                        os.remove(full_path)
                        app.logger.info(f"[purge] Deleted face image: {full_path}")
                except OSError as e:
                    app.logger.warning(
                        f"[purge] Could not delete face image {full_path}: {e}"
                    )

            # Remove from embedding cache
            embedding_cache.pop(str(emp_id), None)
            face_mismatch_counts.pop(str(emp_id), None)

            # Permanently delete employee row (CASCADE removes attendance records)
            cur.execute("DELETE FROM employees WHERE employee_id=%s", (emp_id,))
            cur.execute(
                "DELETE FROM employees_trash WHERE trash_id=%s", (row["trash_id"],)
            )
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
        (key,),
    )
    row = cur.fetchone()
    if row is None:
        return {"fail_count": 0, "locked_until": None, "last_attempt": None}
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
        return {
            "locked": False,
            "seconds_left": 0,
            "fail_count": 0,
            "attempts_left": MAX_ATTEMPTS,
        }

    now = datetime.utcnow()
    locked_until = row.get("locked_until")

    if locked_until and locked_until > now:
        delta = int((locked_until - now).total_seconds())
        return {
            "locked": True,
            "seconds_left": delta,
            "fail_count": row["fail_count"],
            "attempts_left": 0,
        }

    # Not locked (or lockout expired)
    fail_count = row.get("fail_count", 0)
    # If the lockout window expired naturally, treat as if count reset
    if locked_until and locked_until <= now:
        fail_count = 0

    return {
        "locked": False,
        "seconds_left": 0,
        "fail_count": fail_count,
        "attempts_left": max(0, MAX_ATTEMPTS - fail_count),
    }


def record_failed_attempt(username_hash: str, role: str) -> dict:
    """
    Increment the fail counter for (username_hash, role).
    Applies a lockout if MAX_ATTEMPTS is reached.

    Returns the same dict shape as check_lockout() reflecting the new state.
    """
    key = _lockout_key(username_hash, role)
    now = datetime.utcnow()
    try:
        conn = mysql.connection
        cur = conn.cursor(DictCursor)
        row = _get_attempt_row(cur, key)

        # If a previous lockout already expired, reset the counter first
        prev_locked_until = row.get("locked_until")
        if prev_locked_until and prev_locked_until <= now:
            row["fail_count"] = 0

        new_count = (row.get("fail_count") or 0) + 1
        locked_until = None

        if new_count >= MAX_ATTEMPTS:
            from datetime import timedelta

            locked_until = now + timedelta(minutes=LOCKOUT_MINS)

        cur.execute(
            """
            INSERT INTO login_attempts (attempt_key, fail_count, locked_until, last_attempt)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                fail_count   = %s,
                locked_until = %s,
                last_attempt = %s
        """,
            (key, new_count, locked_until, now, new_count, locked_until, now),
        )
        conn.commit()
        cur.close()
    except Exception as exc:
        app.logger.error(f"[lockout] record_failed_attempt error: {exc}")
        return {
            "locked": False,
            "seconds_left": 0,
            "fail_count": 1,
            "attempts_left": MAX_ATTEMPTS - 1,
        }

    if locked_until:
        return {
            "locked": True,
            "seconds_left": LOCKOUT_MINS * 60,
            "fail_count": new_count,
            "attempts_left": 0,
        }
    return {
        "locked": False,
        "seconds_left": 0,
        "fail_count": new_count,
        "attempts_left": max(0, MAX_ATTEMPTS - new_count),
    }


def clear_failed_attempts(username_hash: str, role: str):
    """Reset the fail counter after a successful login."""
    key = _lockout_key(username_hash, role)
    try:
        conn = mysql.connection
        cur = conn.cursor()
        cur.execute("DELETE FROM login_attempts WHERE attempt_key=%s", (key,))
        conn.commit()
        cur.close()
    except Exception as exc:
        app.logger.error(f"[lockout] clear_failed_attempts error: {exc}")


def _lockout_flash(state: dict):
    """
    Produce a user-facing flash message string from a lockout state dict.
    Includes a data attribute the JS countdown timer reads.
    """
    if state["locked"]:
        mins = state["seconds_left"] // 60
        secs = state["seconds_left"] % 60
        return (
            f"LOCKOUT:{state['seconds_left']}:"
            f"Too many failed attempts. Account locked for "
            f"{mins}m {secs:02d}s. Try again later."
        )
    if state["fail_count"] >= WARN_AT:
        left = state["attempts_left"]
        return (
            f"WARN:Invalid credentials — "
            f"{left} attempt{'s' if left != 1 else ''} remaining before lockout."
        )
    return "Invalid credentials. Please check your username and password."


def _dec_emp(row: dict) -> dict:
    """Decrypt all PII fields on an employees row."""
    if row:
        for f in ("username", "full_name", "password", "contact_number"):
            if row.get(f):
                row[f] = aes_decrypt(row[f])
    return row


def _dec_adm(row: dict) -> dict:
    """Decrypt all PII fields on an admins row."""
    if row:
        for f in ("username", "full_name", "password"):
            if row.get(f):
                row[f] = aes_decrypt(row[f])
    return row


# ── Folder for registered face images ──────────────────────────────────────────
UPLOAD_FOLDER = os.path.join("static", "face_images")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

PRODUCT_IMAGE_FOLDER = os.path.join("static", "product_images")
ALLOWED_IMAGE_EXTS = {"jpg", "jpeg", "png", "webp", "gif"}
MAX_PRODUCT_IMAGE_MB = 2
os.makedirs(PRODUCT_IMAGE_FOLDER, exist_ok=True)

# ── MySQL ───────────────────────────────────────────────────────────────────────
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "pos_system"

mysql = MySQL(app)

# ── Performance caches ──────────────────────────────────────────────────────────
embedding_cache = {}  # { employee_id: embedding_vector }
last_frame_time = {}  # { employee_id: datetime }
MIN_FRAME_INTERVAL = 0.8  # seconds between frames per employee

# ── Face-verification security state ────────────────────────────────────────
# One-time tokens issued by /verify_face on success; consumed by /log_attendance.
# Prevents anyone from clocking in without a real, server-confirmed face match.
verified_tokens = {}  # { token: {'employee_id': str, 'expires': datetime} }
VERIFY_TOKEN_TTL = 60  # seconds a verified token stays valid

# Per-employee mismatch lockout — enforced on the SERVER (client timers are bypassable).
face_mismatch_counts = (
    {}
)  # { employee_id: {'count': int, 'locked_until': datetime|None} }
MAX_FACE_MISMATCHES = 3  # hard lockout after this many consecutive mismatches
FACE_LOCKOUT_SECONDS = 30  # lockout duration in seconds

# ── Haar cascade for quick face detection ──────────────────────────────────
face_cascade = cv2.CascadeClassifier(
    cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
)

# ── Liveness session store ──────────────────────────────────────────────────────
# Tracks head-nod challenge state per employee during verification
liveness_sessions = {}

# ── Registration capture store ─────────────────────────────────────────────────
# Temporarily holds multi-frame embeddings during face registration
reg_sessions = (
    {}
)  # { token: { 'embeddings': [], 'best_face': ndarray, 'started': float } }


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         HELPER FUNCTIONS                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def reset_liveness(emp_id):
    """Reset the liveness (anti-spoofing) challenge for an employee."""
    liveness_sessions[emp_id] = {
        "step": "center",  # center → up → down (nod)
        "last_y": None,
        "passed": False,
        "start_time": datetime.now(),
        "stable": 0,  # frames without movement (photo-detection)
    }


def is_admin():
    """
    Return True if the current session has full admin privileges.

    Admins can log in either via the legacy 'admin' role (session['role']=='admin')
    OR via the Manager tab (session['role']=='manager' with session['is_admin']==True).
    All routes that previously checked 'admin_id' in session should call is_admin()
    instead so both paths are covered.
    """
    if session.get("role") == "admin" and "admin_id" in session:
        return True
    if session.get("role") == "manager" and session.get("is_admin") is True:
        return True
    return False


def decode_base64_image(image_data: str):
    """
    Decode a base64 data-URI string to an OpenCV BGR image.
    Returns (img_bgr, gray) or raises ValueError on failure.
    """
    if "," in image_data:
        image_data = image_data.split(",")[1]
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
            raise ValueError(
                f"Image too blurry – hold the camera steady (score: {blur_score:.1f})"
            )

    # ── Haar cascade ─────────────────────────────────────────────────────────
    # Relaxed parameters during registration so dim / slightly off-center
    # faces still detect.  scaleFactor=1.1 catches more scale steps;
    # minNeighbors=3 (vs 5) accepts faces with less repeated confirmation.
    scale = 1.1 if registration_mode else 1.2
    neighbors = 3 if registration_mode else 4
    faces = face_cascade.detectMultiScale(
        gray_eq, scaleFactor=scale, minNeighbors=neighbors, minSize=(50, 50)
    )
    if len(faces) == 0:
        raise ValueError("No face detected – look directly at the camera")

    # Pick largest detected face (most likely to be the subject)
    faces = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)
    (x, y, w, h) = faces[0]

    # ── Distance check ───────────────────────────────────────────────────────
    ratio = (w * h) / (frame_w * frame_h)
    min_ratio = 0.03 if registration_mode else 0.04
    if ratio < min_ratio:
        raise ValueError("Move closer to the camera")
    if ratio > 0.65:
        raise ValueError("Move slightly back from the camera")

    # ── Centering check ──────────────────────────────────────────────────────
    cx, cy = x + w // 2, y + h // 2
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
    face_crop = img[y : y + h, x : x + w]

    # Resize to the exact input size FaceNet-512 expects
    face_crop = cv2.resize(face_crop, (160, 160))

    # ── IMPORTANT: keep as uint8 (0-255) ────────────────────────────────────
    # Dividing by 255 would make this float64 in [0,1].  DeepFace.represent()
    # performs its own internal normalisation; passing a float64 array causes
    # it to crash with a shape/dtype mismatch inside the Keras model.
    # face_crop is already uint8 from cv2.imdecode — do NOT touch it here.

    result = DeepFace.represent(
        img_path=face_crop,
        model_name="Facenet512",
        detector_backend="skip",
        enforce_detection=False,
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
    payload = json.dumps({"v": 1, "emb": embedding_vector}, separators=(",", ":"))
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE employees SET face_model_path=%s WHERE employee_id=%s",
            (payload, employee_id),
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
        (employee_id,),
    )
    row = cur.fetchone()
    if not row:
        return None

    # ── Try JSON embedding first (fast, accurate, no image round-trip) ──────
    model_path = row.get("face_model_path") or ""
    if model_path.startswith("{"):
        try:
            payload = json.loads(model_path)
            emb = payload.get("emb")
            if emb and len(emb) == 512:
                app.logger.info(
                    f"[load_embedding] employee {employee_id}: loaded from DB JSON"
                )
                return emb
        except (json.JSONDecodeError, KeyError):
            pass

    # ── Fallback: re-extract from saved 160×160 face image ──────────────────
    face_image_path = row.get("face_image_path") or ""
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
            img_path=reg_img,
            model_name="Facenet512",
            detector_backend="skip",
            enforce_detection=False,
        )
        emb = reg_result[0]["embedding"]
        app.logger.warning(
            f"[load_embedding] employee {employee_id}: fell back to image re-extraction "
            f"(face_model_path missing). Consider re-registering the face for best accuracy."
        )
        return emb
    except Exception as e:
        app.logger.error(
            f"[load_embedding] image fallback failed for employee {employee_id}: {e}"
        )
        return None


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    FACE REGISTRATION (multi-frame)                          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── Per-token processing lock: prevents concurrent DeepFace calls for the ──
# ── same registration session, which would stack up and crash the server.  ──
reg_locks = set()  # set of tokens currently being processed


@app.route("/register_face_frame", methods=["POST"])
def register_face_frame():
    """
    Called by the employee-management modal to capture one webcam frame
    and extract a FaceNet-512 embedding for registration.

    Sequential safety: if a previous call for the same token is still
    running (DeepFace can take 2–5 s on CPU), this call returns immediately
    with a "busy" response so the client retries on the next tick.
    """
    try:
        data = request.get_json(silent=True) or {}
        token = data.get("token", "")
        image_data = data.get("image", "")

        if not token or not image_data:
            return jsonify(
                {"success": False, "message": "Missing token or image", "captured": 0}
            )

        # ── Concurrent-call guard ────────────────────────────────────────────
        if token in reg_locks:
            return jsonify(
                {
                    "success": False,
                    "message": "Processing… please hold still",
                    "captured": 0,
                }
            )
        reg_locks.add(token)

        try:
            # Initialise session for this registration token if first frame
            if token not in reg_sessions:
                reg_sessions[token] = {
                    "embeddings": [],
                    "best_face": None,
                    "best_sharpness": -1.0,  # track sharpness to pick best crop
                    "started": time.time(),
                }

            sess = reg_sessions[token]

            # ── Expire stale sessions (>5 min) ─────────────────────────────
            if time.time() - sess["started"] > 300:
                del reg_sessions[token]
                return jsonify(
                    {
                        "success": False,
                        "message": "Session expired – restart capture",
                        "captured": 0,
                    }
                )

            # ── Decode & analyse frame ──────────────────────────────────────
            try:
                img, gray = decode_base64_image(image_data)
                # Flip mirrored canvas back to natural orientation for Haar
                img = cv2.flip(img, 1)
                gray = cv2.flip(gray, 1)
                x, y, w, h = detect_face_strict(img, gray, registration_mode=True)
            except ValueError as e:
                return jsonify(
                    {
                        "success": False,
                        "message": str(e),
                        "captured": len(sess["embeddings"]),
                    }
                )

            # ── Extract embedding ───────────────────────────────────────────
            try:
                emb = extract_embedding(img, x, y, w, h)
            except Exception as e:
                return jsonify(
                    {
                        "success": False,
                        "message": f"Embedding error: {e}",
                        "captured": len(sess["embeddings"]),
                    }
                )

            # ── Keep sharpest face crop across all frames ───────────────────
            # Comparing sharpness ensures the saved image (used as visual
            # reference) is the clearest one, even though verification uses
            # the averaged embedding, not this image.
            face_crop = img[y : y + h, x : x + w]
            crop_160 = cv2.resize(face_crop, (160, 160))
            sharp = sharpness_score(crop_160)
            if sharp > sess["best_sharpness"]:
                sess["best_sharpness"] = sharp
                sess["best_face"] = crop_160

            sess["embeddings"].append(emb)
            captured = len(sess["embeddings"])

            step_msgs = {
                1: "⬆️ Now slowly move head UP",
                2: "⬇️ Now move head DOWN",
                3: "✅ Face capture complete",
            }
            msg = step_msgs.get(captured, f"Frame {captured} captured")

            return jsonify({"success": True, "message": msg, "captured": captured})

        finally:
            # ── Always release the lock, even on error ──────────────────────
            reg_locks.discard(token)

    except Exception as e:
        # ── Top-level safety net: never let any exception crash Flask ───────
        return jsonify(
            {"success": False, "message": f"Server error: {e}", "captured": 0}
        )


@app.route("/commit_face_registration", methods=["POST"])
def commit_face_registration():
    """
    Finalize registration: average the captured embeddings, save the sharpest
    face image, persist the averaged embedding to DB, and update the employee record.

    POST JSON:  { "token": str, "employee_id": int }
    Response:   { "success": bool, "message": str }
    """
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    employee_id = data.get("employee_id")

    if not token or not employee_id:
        return jsonify({"success": False, "message": "Missing token or employee_id"})

    sess = reg_sessions.get(token)
    if not sess:
        return jsonify({"success": False, "message": "Registration session not found"})

    if len(sess["embeddings"]) < 2:
        return jsonify(
            {"success": False, "message": "Not enough frames captured (need ≥ 2)"}
        )

    if sess["best_face"] is None:
        return jsonify({"success": False, "message": "No valid face crop available"})

    # ── Save sharpest face image ─────────────────────────────────────────────
    filename = f"{employee_id}.jpg"
    image_path = os.path.join(UPLOAD_FOLDER, filename)
    cv2.imwrite(image_path, sess["best_face"], [cv2.IMWRITE_JPEG_QUALITY, 95])
    face_path = f"face_images/{filename}"

    # ── Average embeddings for best accuracy ────────────────────────────────
    avg_emb = np.mean(sess["embeddings"], axis=0).tolist()

    # ── Persist to DB ───────────────────────────────────────────────────────
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE employees SET face_image_path=%s WHERE employee_id=%s",
            (face_path, employee_id),
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        return jsonify({"success": False, "message": f"DB error: {e}"})

    # ── Persist averaged embedding to face_model_path column ────────────────
    persist_embedding(str(employee_id), avg_emb)

    # ── Clean up registration session ───────────────────────────────────────
    del reg_sessions[token]

    return jsonify({"success": True, "message": "✅ Face ID registered successfully"})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    FACE VERIFICATION (clock-in / out)                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/verify_face", methods=["POST"])
def verify_face():
    """
    Verify a live webcam frame against the employee's registered face embedding.
    Includes liveness detection (head-nod challenge) to prevent photo spoofing.

    POST JSON:
        { "employee_id": str|int, "image": "data:image/jpeg;base64,..." }

    Response JSON:
        { "success": bool, "message": str }
    """
    data = request.get_json(silent=True) or {}
    employee_id = str(data.get("employee_id", ""))
    image_data = data.get("image", "")

    if not employee_id or not image_data:
        return jsonify({"success": False, "message": "Missing data"})

    # ── Session-binding: the requester may ONLY verify their own face ─────────
    # This closes the bypass where an admin/manager selects another employee
    # in the dropdown, completes liveness with their own face, and clocks in
    # as someone else because the face comparison runs against the selected
    # employee's stored FaceID rather than the logged-in user's FaceID.
    _srole = session.get("role", "")
    _semp_id = session.get("employee_id")
    if _srole in ("cashier", "manager"):
        # Non-admin users: employee_id MUST exactly match their own session record
        if str(_semp_id) != employee_id:
            app.logger.warning(
                f"[verify_face] BLOCKED — session employee {_semp_id} "
                f"tried to verify as employee {employee_id} ip={request.remote_addr}"
            )
            return jsonify(
                {
                    "success": False,
                    "message": "\U0001f6ab You can only verify your own identity.",
                    "mismatch": True,
                }
            )
    elif _srole == "admin":
        # Admins: find their linked employee record via matching username_hash
        _admin_id = session.get("admin_id")
        if _admin_id:
            _ca = mysql.connection.cursor(DictCursor)
            _ca.execute(
                "SELECT username_hash FROM admins WHERE admin_id=%s", (_admin_id,)
            )
            _adm = _ca.fetchone()
            if _adm and _adm.get("username_hash"):
                _ca.execute(
                    "SELECT employee_id FROM employees WHERE username_hash=%s LIMIT 1",
                    (_adm["username_hash"],),
                )
                _linked = _ca.fetchone()
                _ca.close()
                if _linked and str(_linked["employee_id"]) != employee_id:
                    app.logger.warning(
                        f"[verify_face] BLOCKED — admin {_admin_id} (emp {_linked['employee_id']}) "
                        f"tried to verify as employee {employee_id} ip={request.remote_addr}"
                    )
                    return jsonify(
                        {
                            "success": False,
                            "message": "\U0001f6ab You can only verify your own identity.",
                            "mismatch": True,
                        }
                    )
            else:
                _ca.close()
    else:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    now = datetime.now()

    # ── Rate-limit per employee (anti-spam) ─────────────────────────────────
    if employee_id in last_frame_time:
        elapsed = (now - last_frame_time[employee_id]).total_seconds()
        if elapsed < MIN_FRAME_INTERVAL:
            return jsonify({"success": False, "message": "Hold still…"})

    # ── Fetch registered face path from DB ──────────────────────────────────
    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT face_image_path FROM employees WHERE employee_id=%s", (employee_id,)
    )
    emp = cur.fetchone()
    cur.close()

    if not emp or not emp.get("face_image_path"):
        return jsonify(
            {"success": False, "message": "No Face ID registered for this employee"}
        )

    # ── Decode & validate incoming frame ────────────────────────────────────
    try:
        img, gray = decode_base64_image(image_data)
        # The browser mirrors the canvas — flip back to natural orientation
        # so Haar detection works correctly (trained on unmirrored faces).
        img = cv2.flip(img, 1)
        gray = cv2.flip(gray, 1)
        x, y, w, h = detect_face_strict(img, gray)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)})

    # ── Rate-limit: update timestamp here so it applies during liveness too ─
    last_frame_time[employee_id] = now

    # ── Server-side mismatch lockout ─────────────────────────────────────────
    # Client-side timers (isMismatchLocked) are bypassable via DevTools or
    # direct HTTP requests. This lockout is enforced purely on the server.
    fm = face_mismatch_counts.get(employee_id, {"count": 0, "locked_until": None})
    if fm["locked_until"] and now < fm["locked_until"]:
        secs_left = int((fm["locked_until"] - now).total_seconds()) + 1
        return jsonify(
            {
                "success": False,
                "message": f"\U0001f512 Too many failed attempts. Try again in {secs_left}s.",
                "locked": True,
            }
        )

    # ── Liveness challenge (head-nod: up → down) ─────────────────────────────
    if employee_id not in liveness_sessions:
        reset_liveness(employee_id)

    s = liveness_sessions[employee_id]

    # Expire challenge after 20 s
    if (now - s["start_time"]).seconds > 20:
        reset_liveness(employee_id)
        return jsonify(
            {
                "success": False,
                "message": "\u23f1\ufe0f Challenge expired – look at camera and try again",
            }
        )

    center_y = y + h // 2

    if s["last_y"] is None:
        s["last_y"] = center_y
        return jsonify(
            {
                "success": False,
                "message": "\u2b06\ufe0f Please move your head UP slowly",
            }
        )

    move = center_y - s["last_y"]  # negative = moved up, positive = moved down

    # Anti-photo: reject if face has been perfectly static for >6 frames
    if abs(move) < 3:
        s["stable"] += 1
    else:
        s["stable"] = 0

    if s["stable"] > 6:
        return jsonify(
            {
                "success": False,
                "message": "\U0001f6ab Static image detected – please move your head",
            }
        )

    # ── Always update last_y so movement is measured frame-to-frame ─────────
    s["last_y"] = center_y

    if s["step"] == "center":
        if move < -8:
            s["step"] = "up"
            return jsonify(
                {
                    "success": False,
                    "message": "\u2b07\ufe0f Good! Now move your head DOWN",
                }
            )
        return jsonify({"success": False, "message": "\u2b06\ufe0f Move your head UP"})

    elif s["step"] == "up":
        if move > 8:
            s["passed"] = True

    if not s["passed"]:
        return jsonify(
            {"success": False, "message": "\u2b07\ufe0f Keep moving your head DOWN"}
        )

    # ── Liveness passed — reset BEFORE any return below ─────────────────────
    # Resetting here ensures that embedding errors, DB errors, or any early
    # return cannot leave passed=True. Without this, the next frame would skip
    # liveness entirely and go straight to face matching.
    reset_liveness(employee_id)

    # ── Perform face match ───────────────────────────────────────────────────
    try:
        captured_emb = extract_embedding(img, x, y, w, h)
    except Exception as e:
        return jsonify({"success": False, "message": f"Embedding error: {e}"})

    if employee_id not in embedding_cache:
        cur2 = mysql.connection.cursor(DictCursor)
        emb = load_embedding_from_db(employee_id, cur2)
        cur2.close()
        if emb is None:
            return jsonify(
                {
                    "success": False,
                    "message": "No registered Face ID found – please re-register",
                }
            )
        embedding_cache[employee_id] = emb

    registered_emb = embedding_cache[employee_id]
    distance = cosine_distance(captured_emb, registered_emb)

    last_frame_time[employee_id] = now

    MATCH_THRESHOLD = 0.30
    if distance >= MATCH_THRESHOLD:
        # ── Increment server-side mismatch counter ───────────────────────────
        fm = face_mismatch_counts.get(employee_id, {"count": 0, "locked_until": None})
        fm["count"] += 1
        attempts_left = max(0, MAX_FACE_MISMATCHES - fm["count"])

        # Log every mismatch to DB
        try:
            mlog_cur = mysql.connection.cursor()
            mlog_cur.execute(
                """INSERT INTO face_mismatch_log
                   (employee_id, distance_score, ip_address, user_agent)
                   VALUES (%s, %s, %s, %s)""",
                (
                    employee_id,
                    round(distance, 4),
                    request.remote_addr,
                    (request.user_agent.string or "")[:255],
                ),
            )
            mysql.connection.commit()
            mlog_cur.close()
        except Exception as log_err:
            app.logger.error(f"[face_mismatch_log] write failed: {log_err}")

        if fm["count"] >= MAX_FACE_MISMATCHES:
            fm["locked_until"] = datetime.now() + __import__("datetime").timedelta(
                seconds=FACE_LOCKOUT_SECONDS
            )
            fm["count"] = 0
            face_mismatch_counts[employee_id] = fm
            return jsonify(
                {
                    "success": False,
                    "message": f"\U0001f512 Too many failed attempts. Locked for {FACE_LOCKOUT_SECONDS}s.",
                    "mismatch": True,
                    "locked": True,
                }
            )

        face_mismatch_counts[employee_id] = fm
        return jsonify(
            {
                "success": False,
                "message": f"\U0001f6ab Face does not match. {attempts_left} attempt(s) left before lockout.",
                "mismatch": True,
            }
        )

    # ── Match confirmed — clear mismatch counter ─────────────────────────────
    face_mismatch_counts.pop(employee_id, None)

    # ── Issue a one-time signed token ────────────────────────────────────────
    # /log_attendance REQUIRES this token. This closes the bypass where someone
    # POSTs directly to /log_attendance without ever passing face verification.
    # The token is tied to the specific employee_id and expires in VERIFY_TOKEN_TTL s.
    verify_token = secrets.token_urlsafe(32)
    verified_tokens[verify_token] = {
        "employee_id": employee_id,
        "expires": datetime.now()
        + __import__("datetime").timedelta(seconds=VERIFY_TOKEN_TTL),
    }
    # Purge expired tokens to prevent unbounded memory growth
    _now = datetime.now()
    for _t in [t for t, v in list(verified_tokens.items()) if v["expires"] < _now]:
        verified_tokens.pop(_t, None)

    return jsonify(
        {
            "success": True,
            "message": "\u2705 Identity verified. Welcome!",
            "verify_token": verify_token,
        }
    )


@app.route("/api/face_mismatch_log", methods=["GET"])
def api_face_mismatch_log():
    """
    Admin-only: return recent face mismatch attempts for security audit.
    Optional query params: ?employee_id=N&limit=50
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    employee_id = request.args.get("employee_id")
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
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
            (employee_id, limit),
        )
    else:
        cur.execute(
            """SELECT fml.id, fml.employee_id, e.full_name,
                      fml.distance_score, fml.attempted_at, fml.ip_address
               FROM face_mismatch_log fml
               LEFT JOIN employees e ON e.employee_id = fml.employee_id
               ORDER BY fml.attempted_at DESC LIMIT %s""",
            (limit,),
        )
    rows = cur.fetchall()
    cur.close()
    # Decrypt full_name for display
    for row in rows:
        if row.get("full_name"):
            row["full_name"] = aes_decrypt(row["full_name"]) or row["full_name"]
        if row.get("attempted_at"):
            row["attempted_at"] = str(row["attempted_at"])
    return jsonify({"success": True, "mismatches": rows})


@app.errorhandler(500)
def handle_500(e):
    """Return JSON for any unhandled 500 error so the server stays up."""
    return jsonify({"success": False, "message": f"Internal server error: {e}"}), 500


@app.route("/reset_liveness", methods=["POST"])
def reset_liveness_route():
    """
    Called by the frontend when the user enters Step 3 (Face Verify).
    Clears any stale liveness session so the challenge always starts fresh
    — prevents a user from getting stuck in a partial challenge state from
    a previous attempt.
    """
    data = request.get_json(silent=True) or {}
    employee_id = str(data.get("employee_id", ""))
    if employee_id and employee_id in liveness_sessions:
        reset_liveness(employee_id)
    return jsonify({"success": True})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         LOGIN / LOGOUT                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/")
def root():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form.get("login_role", "").strip()
        username = (request.form.get(f"{role}Username") or "").strip()
        password = (request.form.get(f"{role}Password") or "").strip()

        if not username or not password:
            flash("Please enter both username and password.")
            return render_template("index.html")

        u_hash = aes_username_hash(username)

        # ── Lockout check — must happen before any DB credential query ────────
        # We check *both* the specific role key AND a shared "any-role" key so
        # that attackers cannot bypass a cashier lockout by switching to manager.
        lockout_role_key = role  # per-role key (independent counters per tab)
        state = check_lockout(u_hash, lockout_role_key)
        if state["locked"]:
            flash(_lockout_flash(state))
            return render_template("index.html")

        cur = mysql.connection.cursor(DictCursor)
        auth_ok = False
        redirect_to = None

        # ── Legacy admin tab ─────────────────────────────────────────────────
        if role == "admin":
            cur.execute("SELECT * FROM admins WHERE username_hash=%s", (u_hash,))
            user = _dec_adm(cur.fetchone())
            if user and _check_login_password(password, user):
                session.clear()
                session["admin_id"] = user["admin_id"]
                session["role"] = "admin"
                session["is_admin"] = True
                session["full_name"] = (user.get("full_name") or "Admin").strip()
                auth_ok = True
                redirect_to = url_for("dashboard")

        # ── Manager tab ──────────────────────────────────────────────────────
        elif role == "manager":
            cur.execute(
                """SELECT * FROM employees WHERE username_hash=%s
                   AND role='manager' AND employment_status='active'""",
                (u_hash,),
            )
            employee = _dec_emp(cur.fetchone())
            if employee and _check_login_password(password, employee):
                session.clear()
                session["employee_id"] = employee["employee_id"]
                session["role"] = "manager"
                session["is_admin"] = False
                session["full_name"] = (employee.get("full_name") or "Manager").strip()
                cur.execute(
                    "UPDATE employees SET last_login=NOW() WHERE employee_id=%s",
                    (employee["employee_id"],),
                )
                mysql.connection.commit()
                auth_ok = True
                redirect_to = url_for("dashboard")
            else:
                # Fallback: try admins table via Manager tab
                cur.execute("SELECT * FROM admins WHERE username_hash=%s", (u_hash,))
                admin = _dec_adm(cur.fetchone())
                if admin and _check_login_password(password, admin):
                    session.clear()
                    session["admin_id"] = admin["admin_id"]
                    session["role"] = "admin"
                    session["is_admin"] = True
                    session["full_name"] = (admin.get("full_name") or "Admin").strip()
                    auth_ok = True
                    redirect_to = url_for("dashboard")

        # ── Cashier tab ──────────────────────────────────────────────────────
        elif role == "cashier":
            cur.execute(
                """SELECT * FROM employees WHERE username_hash=%s
                   AND role='cashier' AND employment_status='active'""",
                (u_hash,),
            )
            user = _dec_emp(cur.fetchone())
            if user and _check_login_password(password, user):
                session.clear()
                session["employee_id"] = user["employee_id"]
                session["role"] = "cashier"
                session["is_admin"] = False
                session["full_name"] = (user.get("full_name") or "Cashier").strip()
                cur.execute(
                    "UPDATE employees SET last_login=NOW() WHERE employee_id=%s",
                    (user["employee_id"],),
                )
                mysql.connection.commit()
                auth_ok = True
                redirect_to = url_for("cashier_dashboard")

        cur.close()

        if auth_ok:
            # ── Successful login: clear the fail counter ──────────────────────
            clear_failed_attempts(u_hash, lockout_role_key)
            return redirect(redirect_to)

        # ── Failed login: increment counter, apply lockout if threshold hit ──
        new_state = record_failed_attempt(u_hash, lockout_role_key)
        flash(_lockout_flash(new_state))

    return render_template("index.html")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         DASHBOARD                                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/dashboard")
def dashboard():
    if session.get("role") not in ["admin", "manager"]:
        return redirect(url_for("login"))

    # ── Resolve full_name ──────────────────────────────────────────────────────
    full_name = session.get("full_name")
    if not full_name:
        cur = mysql.connection.cursor(DictCursor)
        if session["role"] == "admin":
            cur.execute(
                "SELECT full_name FROM admins WHERE admin_id=%s", (session["admin_id"],)
            )
            user = _dec_adm(cur.fetchone())
        else:
            cur.execute(
                "SELECT full_name FROM employees WHERE employee_id=%s",
                (session["employee_id"],),
            )
            user = _dec_emp(cur.fetchone())
        full_name = (
            user["full_name"] if user else session["role"].capitalize()
        ).strip()
        cur.close()

    # ── Inventory: low-stock items (uses shared helper) ────────────────────
    try:
        low_stock_items = _get_low_stock_items(limit=20)
    except Exception as exc:
        app.logger.error(f"[dashboard] low-stock query failed: {exc}")
        low_stock_items = []
    low_stock_count = len(low_stock_items)

    # ── Sales data from transactions table ───────────────────────────────────
    today_sales = None
    sales_change = 0
    transaction_count = None
    transaction_change = 0
    top_product_name = None
    top_product_units = 0
    sales_chart_data = []
    recent_transactions = []
    top_products = []

    try:
        cur = mysql.connection.cursor(DictCursor)

        # ── Today's sales & transaction count ─────────────────────────────────
        cur.execute(
            """
            SELECT
                COALESCE(SUM(total_amount), 0)  AS today_total,
                COUNT(*)                         AS today_count
            FROM transactions
            WHERE DATE(created_at) = CURDATE()
              AND status = 'completed'
        """
        )
        row = cur.fetchone()
        today_total_raw = float(row["today_total"])
        today_count_raw = int(row["today_count"])
        today_sales = f"{today_total_raw:,.2f}"
        transaction_count = today_count_raw

        # ── Yesterday's sales & transaction count (for % change) ──────────────
        cur.execute(
            """
            SELECT
                COALESCE(SUM(total_amount), 0) AS yest_total,
                COUNT(*)                        AS yest_count
            FROM transactions
            WHERE DATE(created_at) = CURDATE() - INTERVAL 1 DAY
              AND status = 'completed'
        """
        )
        yrow = cur.fetchone()
        yest_total = float(yrow["yest_total"])
        yest_count = int(yrow["yest_count"])

        if yest_total > 0:
            sales_change = round((today_total_raw - yest_total) / yest_total * 100, 1)
        if yest_count > 0:
            transaction_change = round(
                (today_count_raw - yest_count) / yest_count * 100, 1
            )

        # ── Top-selling product today ──────────────────────────────────────────
        cur.execute(
            """
            SELECT ti.product_name, ti.category_name,
                   SUM(ti.quantity) AS units_sold
            FROM transaction_items ti
            JOIN transactions t ON t.transaction_id = ti.transaction_id
            WHERE DATE(t.created_at) = CURDATE()
              AND t.status = 'completed'
            GROUP BY ti.product_name, ti.category_name
            ORDER BY units_sold DESC
            LIMIT 1
        """
        )
        top_row = cur.fetchone()
        if top_row:
            top_product_name = top_row["product_name"]
            top_product_units = int(top_row["units_sold"])

        # ── Recent transactions (last 10) ──────────────────────────────────────
        cur.execute(
            """
            SELECT t.transaction_id, t.total_amount,
                   t.created_at,
                   COUNT(ti.item_id)             AS item_count,
                   MIN(ti.category_name)         AS category
            FROM transactions t
            LEFT JOIN transaction_items ti ON ti.transaction_id = t.transaction_id
            WHERE t.status = 'completed'
            GROUP BY t.transaction_id
            ORDER BY t.created_at DESC
            LIMIT 10
        """
        )
        now_dt = datetime.now()
        for r in cur.fetchall():
            diff = now_dt - r["created_at"]
            secs = int(diff.total_seconds())
            if secs < 60:
                time_ago = f"{secs}s ago"
            elif secs < 3600:
                time_ago = f"{secs // 60}m ago"
            elif secs < 86400:
                time_ago = f"{secs // 3600}h ago"
            else:
                time_ago = f"{secs // 86400}d ago"
            recent_transactions.append(
                {
                    "id": r["transaction_id"],
                    "amount": f"{float(r['total_amount']):,.2f}",
                    "item_count": int(r["item_count"] or 0),
                    "category": r["category"] or "—",
                    "time_ago": time_ago,
                }
            )

        # ── Top products (all-time, up to 10) ─────────────────────────────────
        cur.execute(
            """
            SELECT ti.product_name      AS name,
                   ti.category_name     AS category,
                   SUM(ti.quantity)     AS units_sold,
                   SUM(ti.line_total)   AS revenue
            FROM transaction_items ti
            JOIN transactions t ON t.transaction_id = ti.transaction_id
            WHERE t.status = 'completed'
            GROUP BY ti.product_name, ti.category_name
            ORDER BY units_sold DESC
            LIMIT 10
        """
        )
        for r in cur.fetchall():
            top_products.append(
                {
                    "name": r["name"],
                    "category": r["category"] or "—",
                    "units_sold": int(r["units_sold"]),
                    "revenue": f"{float(r['revenue']):,.2f}",
                }
            )

        # ── Sales chart — last 7 days ──────────────────────────────────────────
        cur.execute(
            """
            SELECT DATE(created_at) AS day,
                   COALESCE(SUM(total_amount), 0) AS total
            FROM transactions
            WHERE created_at >= CURDATE() - INTERVAL 6 DAY
              AND status = 'completed'
            GROUP BY DATE(created_at)
            ORDER BY day ASC
        """
        )
        chart_rows = {str(r["day"]): float(r["total"]) for r in cur.fetchall()}

        from datetime import date as _date, timedelta as _td

        day_labels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        week_days = [(_date.today() - _td(days=6 - i)) for i in range(7)]
        week_totals = [chart_rows.get(str(d), 0.0) for d in week_days]
        max_total = max(week_totals) if any(week_totals) else 1
        for d, total in zip(week_days, week_totals):
            sales_chart_data.append(
                {
                    "day": day_labels[d.weekday() + 1 if d.weekday() < 6 else 0],
                    "label": f"{total:,.0f}" if total else "0",
                    "height_pct": round(total / max_total * 90, 1) if max_total else 5,
                }
            )

        cur.close()
    except Exception as exc:
        app.logger.error(f"[dashboard] sales query failed: {exc}")

    return render_template(
        "dashboard.html",
        full_name=full_name,
        # summary cards
        today_sales=today_sales,
        sales_change=sales_change,
        transaction_count=transaction_count,
        transaction_change=transaction_change,
        low_stock_count=low_stock_count,
        new_low_stock_count=low_stock_count,
        top_product_name=top_product_name,
        top_product_units=top_product_units,
        # chart & tables
        sales_chart_data=sales_chart_data,
        recent_transactions=recent_transactions,
        low_stock_items=low_stock_items,
        top_products=top_products,
    )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                       EMPLOYEE MANAGEMENT                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/employee_management")
def employee_management():
    if session.get("role") not in ["admin", "manager"]:
        return redirect(url_for("login"))

    cur = mysql.connection.cursor(DictCursor)

    if session["role"] == "admin":
        cur.execute(
            "SELECT full_name FROM admins WHERE admin_id=%s", (session["admin_id"],)
        )
        user = _dec_adm(cur.fetchone())
    else:
        cur.execute(
            "SELECT full_name FROM employees WHERE employee_id=%s",
            (session["employee_id"],),
        )
        user = _dec_emp(cur.fetchone())
    full_name = user["full_name"] if user else session["role"].capitalize()

    cur.execute(
        """
        SELECT employee_id, full_name, username, role, contact_number,
               employment_status, face_image_path, face_model_path,
               last_login, created_at,
               COALESCE(hourly_rate, 0) AS hourly_rate
        FROM employees
        ORDER BY created_at DESC
    """
    )
    employees = [_dec_emp(row) for row in cur.fetchall()]
    cur.close()

    return render_template(
        "employee_management.html", full_name=full_name, employees=employees
    )


@app.route("/add_employee", methods=["POST"])
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
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    full_name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "").strip()
    contact = request.form.get("contact", "").strip()
    status = request.form.get("status", "active")
    try:
        hourly_rate = float(request.form.get("hourly_rate", 0) or 0)
    except (ValueError, TypeError):
        hourly_rate = 0.0

    if not all([full_name, username, password, role, contact]):
        return jsonify({"success": False, "message": "All fields are required"})

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """INSERT INTO employees
               (full_name, username, username_hash, password, password_hash,
                role, contact_number, employment_status, hourly_rate)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                aes_encrypt(full_name),
                aes_encrypt(username),
                aes_username_hash(username),
                aes_encrypt(password),
                hash_password(password),
                role,
                aes_encrypt(contact),
                status,
                hourly_rate,
            ),
        )
        employee_id = cur.lastrowid

        # ── Process uploaded face frames ─────────────────────────────────────
        files = request.files.getlist("face_images[]")
        embeddings = []
        best_face = None
        best_sharp_ae = -1.0

        for file in files:
            file_bytes = np.frombuffer(file.read(), np.uint8)
            img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            if img is None:
                continue

            try:
                # Browser canvas is mirrored – flip to natural orientation
                img = cv2.flip(img, 1)
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                x, y, w, h = detect_face_strict(img, gray, registration_mode=True)
                emb = extract_embedding(img, x, y, w, h)
                embeddings.append(emb)
                # Pick sharpest crop across all frames
                crop = img[y : y + h, x : x + w]
                crop_160 = cv2.resize(crop, (160, 160))
                sharp = sharpness_score(crop_160)
                if sharp > best_sharp_ae:
                    best_sharp_ae = sharp
                    best_face = crop_160
            except (ValueError, Exception):
                continue

        if len(embeddings) < 1:
            mysql.connection.rollback()
            cur.close()
            return jsonify(
                {
                    "success": False,
                    "message": "No face detected in captured frames – please retake",
                }
            )

        # ── Save sharpest face image ─────────────────────────────────────────
        filename = f"{employee_id}.jpg"
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        cv2.imwrite(image_path, best_face, [cv2.IMWRITE_JPEG_QUALITY, 95])
        face_path = f"face_images/{filename}"

        cur.execute(
            "UPDATE employees SET face_image_path=%s WHERE employee_id=%s",
            (face_path, employee_id),
        )
        mysql.connection.commit()
        cur.close()

        # ── Persist averaged embedding to DB (face_model_path) ───────────────
        avg_emb = np.mean(embeddings, axis=0).tolist()
        persist_embedding(str(employee_id), avg_emb)

        return jsonify(
            {
                "success": True,
                "message": "Employee registered with Face ID ✅",
                "employee_id": employee_id,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route("/update_employee/<int:employee_id>", methods=["POST"])
def update_employee(employee_id):
    """Update employee details; also re-registers Face ID if new face_images[] are provided."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    full_name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "").strip()
    contact = request.form.get("contact", "").strip()
    status = request.form.get("status", "").strip()
    try:
        hourly_rate = float(request.form.get("hourly_rate", 0) or 0)
    except (ValueError, TypeError):
        hourly_rate = 0.0

    enc_name = aes_encrypt(full_name)
    enc_username = aes_encrypt(username)
    enc_contact = aes_encrypt(contact)
    u_hash = aes_username_hash(username)

    try:
        cur = mysql.connection.cursor()

        files = request.files.getlist("face_images[]")
        embeddings = []
        best_face = None
        best_sharp_ue = -1.0

        for file in files:
            file_bytes = np.frombuffer(file.read(), np.uint8)
            img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            if img is None:
                continue
            try:
                # Browser canvas is mirrored – flip to natural orientation
                # (was missing in update_employee — caused orientation mismatch)
                img = cv2.flip(img, 1)
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                x, y, w, h = detect_face_strict(img, gray, registration_mode=True)
                emb = extract_embedding(img, x, y, w, h)
                embeddings.append(emb)
                # Pick sharpest crop across all frames
                crop = img[y : y + h, x : x + w]
                crop_160 = cv2.resize(crop, (160, 160))
                sharp = sharpness_score(crop_160)
                if sharp > best_sharp_ue:
                    best_sharp_ue = sharp
                    best_face = crop_160
            except (ValueError, Exception):
                continue

        if embeddings and best_face is not None:
            # New face registered during edit
            filename = f"{employee_id}.jpg"
            image_path = os.path.join(UPLOAD_FOLDER, filename)
            cv2.imwrite(image_path, best_face, [cv2.IMWRITE_JPEG_QUALITY, 95])
            face_path = f"face_images/{filename}"

            cur.execute(
                """UPDATE employees
                   SET full_name=%s, username=%s, username_hash=%s, role=%s,
                       contact_number=%s, employment_status=%s, face_image_path=%s,
                       hourly_rate=%s
                   WHERE employee_id=%s""",
                (
                    enc_name,
                    enc_username,
                    u_hash,
                    role,
                    enc_contact,
                    status,
                    face_path,
                    hourly_rate,
                    employee_id,
                ),
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
                (
                    enc_name,
                    enc_username,
                    u_hash,
                    role,
                    enc_contact,
                    status,
                    hourly_rate,
                    employee_id,
                ),
            )

        mysql.connection.commit()
        cur.close()
        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route("/delete_employee/<int:employee_id>", methods=["DELETE"])
def delete_employee(employee_id):
    """
    Move an employee to the trash (employees_trash table).
    The employee is set to 'inactive' immediately and permanently deleted
    from the database after a 24-hour grace period.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        import datetime as _dt

        cur = mysql.connection.cursor(DictCursor)

        # Fetch the full employee row before touching it
        cur.execute(
            """
            SELECT employee_id, full_name, username, username_hash,
                   password, password_hash, role, contact_number,
                   face_image_path, face_model_path, last_login,
                   created_at, disabled_at
            FROM employees WHERE employee_id=%s LIMIT 1
        """,
            (employee_id,),
        )
        emp = cur.fetchone()

        if not emp:
            cur.close()
            return jsonify({"success": False, "message": "Employee not found"}), 404

        # Check not already in trash
        cur.execute(
            "SELECT trash_id FROM employees_trash WHERE employee_id=%s LIMIT 1",
            (employee_id,),
        )
        if cur.fetchone():
            cur.close()
            return (
                jsonify({"success": False, "message": "Employee is already in trash"}),
                400,
            )

        now = datetime.now()
        delete_at = now + _dt.timedelta(hours=24)

        # Insert snapshot into trash
        cur.execute(
            """
            INSERT INTO employees_trash
                (employee_id, full_name, username, username_hash,
                 password, password_hash, role, contact_number,
                 face_image_path, face_model_path, last_login,
                 created_at, disabled_at, delete_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
            (
                emp["employee_id"],
                emp["full_name"],
                emp["username"],
                emp["username_hash"],
                emp["password"],
                emp["password_hash"],
                emp["role"],
                emp["contact_number"],
                emp["face_image_path"],
                emp["face_model_path"],
                emp["last_login"],
                emp["created_at"],
                now,
                delete_at,
            ),
        )

        # Soft-disable the live row so they can't log in
        cur.execute(
            "UPDATE employees SET employment_status='inactive', disabled_at=%s WHERE employee_id=%s",
            (now, employee_id),
        )
        mysql.connection.commit()
        cur.close()

        # Invalidate caches
        embedding_cache.pop(str(employee_id), None)
        face_mismatch_counts.pop(str(employee_id), None)

        app.logger.info(
            f"[trash] Employee #{employee_id} moved to trash, delete_at={delete_at}"
        )
        return jsonify(
            {
                "success": True,
                "message": "Employee moved to trash. Will be permanently deleted in 24 hours.",
                "delete_at": delete_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route("/api/trash", methods=["GET"])
def api_trash():
    """Admin-only: list all employees currently in the trash with time remaining."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        """
        SELECT trash_id, employee_id, full_name, role,
               disabled_at, delete_at,
               GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), delete_at)) AS seconds_remaining
        FROM employees_trash
        ORDER BY delete_at ASC
    """
    )
    rows = cur.fetchall()
    cur.close()

    for row in rows:
        if row.get("full_name"):
            row["full_name"] = aes_decrypt(row["full_name"]) or row["full_name"]
        if row.get("disabled_at"):
            row["disabled_at"] = str(row["disabled_at"])
        if row.get("delete_at"):
            row["delete_at"] = str(row["delete_at"])

    return jsonify({"success": True, "trash": rows})


@app.route("/restore_employee/<int:employee_id>", methods=["POST"])
def restore_employee(employee_id):
    """
    Restore an employee from the trash back to active status.
    Removes the trash entry and re-activates the employee row.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        cur = mysql.connection.cursor(DictCursor)

        cur.execute(
            "SELECT trash_id FROM employees_trash WHERE employee_id=%s LIMIT 1",
            (employee_id,),
        )
        trash_row = cur.fetchone()
        if not trash_row:
            cur.close()
            return (
                jsonify({"success": False, "message": "Employee not found in trash"}),
                404,
            )

        # Re-activate the live row
        cur.execute(
            "UPDATE employees SET employment_status='active', disabled_at=NULL WHERE employee_id=%s",
            (employee_id,),
        )
        # Remove from trash
        cur.execute(
            "DELETE FROM employees_trash WHERE trash_id=%s", (trash_row["trash_id"],)
        )
        mysql.connection.commit()
        cur.close()

        app.logger.info(f"[trash] Employee #{employee_id} restored from trash")
        return jsonify({"success": True, "message": "Employee restored successfully."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


# ── Invalidate embedding cache when called externally ──────────────────────────
@app.route("/invalidate_face_cache/<int:employee_id>", methods=["POST"])
def invalidate_face_cache(employee_id):
    """Remove a cached embedding so the next verification re-reads from disk."""
    if session.get("role") not in ["admin", "manager"]:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    embedding_cache.pop(str(employee_id), None)
    return jsonify({"success": True, "message": "Cache cleared"})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                       STAFF ATTENDANCE                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/staff_attendance")
def staff_attendance():
    if session.get("role") not in ["admin", "manager"]:
        return redirect(url_for("login"))

    cur = mysql.connection.cursor(DictCursor)
    if session["role"] == "admin":
        cur.execute(
            "SELECT full_name FROM admins WHERE admin_id=%s", (session["admin_id"],)
        )
        user = _dec_adm(cur.fetchone())
    else:
        cur.execute(
            "SELECT full_name FROM employees WHERE employee_id=%s",
            (session["employee_id"],),
        )
        user = _dec_emp(cur.fetchone())
    full_name = user["full_name"] if user else session["role"].capitalize()
    cur.close()

    return render_template("staff_attendance.html", full_name=full_name)


@app.route("/log_attendance", methods=["POST"])
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
    if "employee_id" not in session and not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    action = data.get("action")
    shift_type = data.get("shift_type")
    verify_token = data.get("verify_token", "")

    if not all([action, shift_type, verify_token]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

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
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Face verification required before clocking in/out.",
                }
            ),
            403,
        )

    # Derive employee_id exclusively from the token — ignore request body value
    employee_id = token_data["employee_id"]
    employee_id_str = str(employee_id)

    # Sanity-guard: logged-in session employee must match the face that was verified.
    # This catches any case where the session identity diverges from the verified face.
    session_emp = session.get("employee_id")
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
                (
                    session_emp,
                    None,
                    request.remote_addr,
                    (request.user_agent.string or "")[:255],
                ),
            )
            mysql.connection.commit()
            mlog_cur.close()
        except Exception:
            pass
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Face verification token does not match this employee.",
                }
            ),
            403,
        )

    if datetime.now() > token_data["expires"]:
        verified_tokens.pop(verify_token, None)
        app.logger.warning(
            f"[log_attendance] EXPIRED TOKEN — employee {employee_id_str} ip={request.remote_addr}"
        )
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Verification expired — please verify your face again.",
                }
            ),
            403,
        )

    # ── Token valid — consume it (one-time use) ──────────────────────────────
    verified_tokens.pop(verify_token, None)

    cur = mysql.connection.cursor(DictCursor)

    # Validate employee
    cur.execute(
        "SELECT employee_id, full_name, role, employment_status FROM employees WHERE employee_id=%s LIMIT 1",
        (employee_id,),
    )
    emp = cur.fetchone()
    if not emp:
        cur.close()
        return jsonify({"success": False, "message": "Employee not found"}), 404
    if emp["employment_status"] != "active":
        cur.close()
        return (
            jsonify({"success": False, "message": "Employee account is inactive"}),
            400,
        )
    # Decrypt PII fields so the frontend confirm card shows the real name/role
    if emp.get("full_name"):
        emp["full_name"] = aes_decrypt(emp["full_name"]) or emp["full_name"]

    # Today's attendance record
    cur.execute(
        "SELECT attendance_id, clock_in, clock_out FROM attendance WHERE employee_id=%s AND attendance_date=CURDATE() LIMIT 1",
        (employee_id,),
    )
    record = cur.fetchone()

    if action == "clock_in":
        if record:
            cur.close()
            return (
                jsonify({"success": False, "message": "Already clocked in today"}),
                400,
            )
        cur.execute(
            "INSERT INTO attendance (employee_id, shift_type, clock_in, attendance_date) VALUES (%s, %s, NOW(), CURDATE())",
            (employee_id, shift_type),
        )
        mysql.connection.commit()
        cur.close()
        return jsonify(
            {
                "success": True,
                "message": "Clock-in recorded ✅",
                "employee": emp,
                "action": "clock_in",
                "shift_type": shift_type,
            }
        )

    elif action == "clock_out":
        if not record:
            cur.close()
            return (
                jsonify({"success": False, "message": "No clock-in found for today"}),
                400,
            )
        if record["clock_out"] is not None:
            cur.close()
            return (
                jsonify({"success": False, "message": "Already clocked out today"}),
                400,
            )
        cur.execute(
            "UPDATE attendance SET clock_out=NOW() WHERE attendance_id=%s",
            (record["attendance_id"],),
        )
        mysql.connection.commit()
        # ── Persist payroll columns on clock-out ─────────────────────────────
        _store_clock_out_pay(mysql.connection, record["attendance_id"])
        cur.close()
        return jsonify(
            {
                "success": True,
                "message": "Clock-out recorded ✅",
                "employee": emp,
                "action": "clock_out",
                "shift_type": shift_type,
            }
        )

    cur.close()
    return jsonify({"success": False, "message": "Invalid action"}), 400


@app.route("/api/employees", methods=["GET"])
def api_employees():
    if session.get("role") not in ["admin", "manager"]:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT employee_id, full_name, role FROM employees WHERE employment_status='active' ORDER BY full_name ASC"
    )
    rows = cur.fetchall()
    cur.close()
    for row in rows:
        if row.get("full_name"):
            row["full_name"] = aes_decrypt(row["full_name"])
    return jsonify({"success": True, "employees": rows})


@app.route("/api/attendance", methods=["GET"])
def api_attendance():
    if session.get("role") not in ["admin", "manager"]:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    date_str = request.args.get("date")
    search = (request.args.get("search") or "").strip()

    if date_str:
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            return jsonify({"success": False, "message": "Invalid date format"}), 400
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

    # NOTE: full_name is AES-encrypted in the DB, so SQL LIKE cannot match it.
    # Employee ID search is still done in SQL; name search is applied after decryption.
    if search:
        try:
            emp_id_search = int(search)
            sql += " AND e.employee_id = %s"
            params.append(emp_id_search)
        except ValueError:
            pass  # Not a numeric ID — skip SQL filter; we'll filter by name below

    sql += " ORDER BY a.clock_in DESC"

    cur.execute(sql, tuple(params))
    rows = cur.fetchall()
    cur.close()

    # Decrypt full_name for all rows
    for row in rows:
        if row.get("full_name"):
            row["full_name"] = aes_decrypt(row["full_name"]) or row["full_name"]

    # Apply name search after decryption (encrypted values can't be matched with SQL LIKE)
    if search:
        search_lower = search.lower()
        rows = [
            r
            for r in rows
            if search_lower in (r.get("full_name") or "").lower()
            or search_lower in str(r.get("employee_id", ""))
        ]

    return jsonify({"success": True, "date": str(dt), "records": rows})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         ADMIN SETTINGS                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/admin_settings")
def admin_settings():
    if not is_admin():
        return redirect(url_for("login"))

    cur = mysql.connection.cursor(DictCursor)
    try:
        if session.get("role") == "admin" and "admin_id" in session:
            cur.execute(
                "SELECT full_name FROM admins WHERE admin_id=%s", (session["admin_id"],)
            )
            user = _dec_adm(cur.fetchone())
        else:
            cur.execute(
                "SELECT full_name FROM employees WHERE employee_id=%s",
                (session["employee_id"],),
            )
            user = _dec_emp(cur.fetchone())
        full_name = user["full_name"] if user else session.get("full_name", "Admin")
    except Exception:
        full_name = session.get("full_name", "Admin")
    finally:
        cur.close()

    return render_template("admin_setting.html", full_name=full_name)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    EMAIL ALERT SETTINGS API                                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _ensure_email_settings_table():
    """
    Create the email_alert_settings table if it does not already exist.
    Called lazily on first API access so no manual migration is needed.
    """
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS email_alert_settings (
                id                  INT AUTO_INCREMENT PRIMARY KEY,
                smtp_host           VARCHAR(255)  NOT NULL DEFAULT '',
                smtp_port           SMALLINT      NOT NULL DEFAULT 587,
                smtp_user           VARCHAR(255)  NOT NULL DEFAULT '',
                smtp_password       VARCHAR(255)  NOT NULL DEFAULT '',
                smtp_use_tls        TINYINT(1)    NOT NULL DEFAULT 1,
                alert_recipient     VARCHAR(255)  NOT NULL DEFAULT '',
                low_stock_enabled   TINYINT(1)    NOT NULL DEFAULT 1,
                low_stock_threshold INT           NOT NULL DEFAULT 5,
                daily_summary_enabled       TINYINT(1) NOT NULL DEFAULT 1,
                new_employee_enabled        TINYINT(1) NOT NULL DEFAULT 0,
                failed_login_enabled        TINYINT(1) NOT NULL DEFAULT 1,
                maintenance_enabled         TINYINT(1) NOT NULL DEFAULT 0,
                updated_at          TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
                                    ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        # Seed one default row so GET always returns something
        cur.execute("SELECT COUNT(*) AS cnt FROM email_alert_settings")
        if cur.fetchone()[0] == 0:
            cur.execute(
                "INSERT INTO email_alert_settings "
                "(smtp_host, smtp_port, smtp_user, smtp_password, smtp_use_tls, "
                " alert_recipient, low_stock_enabled, low_stock_threshold) "
                "VALUES ('smtp.gmail.com', 587, '', '', 1, '', 1, 5)"
            )
        mysql.connection.commit()
        cur.close()
    except Exception as exc:
        app.logger.error(f"[email_settings] table creation failed: {exc}")


# ── GET  /api/settings/email ──────────────────────────────────────────────────
@app.route("/api/settings/email", methods=["GET"])
def api_get_email_settings():
    """Return the current email / alert configuration (password masked)."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    _ensure_email_settings_table()
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT * FROM email_alert_settings ORDER BY id LIMIT 1")
        row = cur.fetchone()
        cur.close()
        if not row:
            return jsonify({"success": False, "message": "No settings found"}), 404
        # Never return the raw SMTP password to the browser
        row["smtp_password"] = "••••••••" if row.get("smtp_password") else ""
        row["has_password"] = bool(row.get("smtp_password") or
                                   row["smtp_password"] == "••••••••")
        return jsonify({"success": True, "settings": row})
    except Exception as exc:
        app.logger.error(f"[email_settings] GET: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── POST /api/settings/email ──────────────────────────────────────────────────
@app.route("/api/settings/email", methods=["POST"])
def api_save_email_settings():
    """
    Persist SMTP configuration and per-alert toggle states.
    Accepts JSON body with any subset of the settings columns.
    The SMTP password is only updated when the client sends a non-placeholder value.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    _ensure_email_settings_table()

    data = request.get_json(silent=True) or {}

    # Build SET clause dynamically from allowed fields
    allowed = {
        "smtp_host", "smtp_port", "smtp_user", "smtp_use_tls",
        "alert_recipient",
        "low_stock_enabled", "low_stock_threshold",
        "daily_summary_enabled", "new_employee_enabled",
        "failed_login_enabled", "maintenance_enabled",
    }
    updates = {k: v for k, v in data.items() if k in allowed}

    # Only update password if the client sent a real new one (not the placeholder)
    new_pass = data.get("smtp_password", "")
    if new_pass and new_pass != "••••••••":
        updates["smtp_password"] = new_pass

    if not updates:
        return jsonify({"success": False, "message": "Nothing to update"}), 400

    try:
        cur = mysql.connection.cursor(DictCursor)

        # Ensure the row exists
        cur.execute("SELECT id FROM email_alert_settings ORDER BY id LIMIT 1")
        row = cur.fetchone()

        set_clause = ", ".join(f"`{k}` = %s" for k in updates)
        values = list(updates.values())

        if row:
            cur.execute(
                f"UPDATE email_alert_settings SET {set_clause} WHERE id = %s",
                values + [row["id"]],
            )
        else:
            cols = ", ".join(f"`{k}`" for k in updates)
            placeholders = ", ".join(["%s"] * len(updates))
            cur.execute(
                f"INSERT INTO email_alert_settings ({cols}) VALUES ({placeholders})",
                values,
            )

        mysql.connection.commit()
        cur.close()
        return jsonify({"success": True, "message": "Settings saved successfully"})
    except Exception as exc:
        app.logger.error(f"[email_settings] POST: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── POST /api/settings/email/auto-configure ──────────────────────────────────
@app.route("/api/settings/email/auto-configure", methods=["POST"])
def api_auto_configure_email():
    """
    Detect the SMTP provider from the email domain and return the
    recommended host / port / TLS settings without saving anything.
    Body: { "email": "user@gmail.com" }
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data  = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()

    if "@" not in email:
        return jsonify({"success": False, "message": "Invalid email address"}), 400

    domain = email.split("@")[1]

    PROVIDERS = {
        "gmail.com":       {"host": "smtp.gmail.com",          "port": 587, "tls": True,  "label": "Gmail"},
        "googlemail.com":  {"host": "smtp.gmail.com",          "port": 587, "tls": True,  "label": "Gmail"},
        "outlook.com":     {"host": "smtp-mail.outlook.com",   "port": 587, "tls": True,  "label": "Outlook"},
        "hotmail.com":     {"host": "smtp-mail.outlook.com",   "port": 587, "tls": True,  "label": "Hotmail"},
        "live.com":        {"host": "smtp-mail.outlook.com",   "port": 587, "tls": True,  "label": "Microsoft Live"},
        "yahoo.com":       {"host": "smtp.mail.yahoo.com",     "port": 587, "tls": True,  "label": "Yahoo Mail"},
        "ymail.com":       {"host": "smtp.mail.yahoo.com",     "port": 587, "tls": True,  "label": "Yahoo Mail"},
        "icloud.com":      {"host": "smtp.mail.me.com",        "port": 587, "tls": True,  "label": "iCloud Mail"},
        "me.com":          {"host": "smtp.mail.me.com",        "port": 587, "tls": True,  "label": "iCloud Mail"},
        "zoho.com":        {"host": "smtp.zoho.com",           "port": 587, "tls": True,  "label": "Zoho Mail"},
        "protonmail.com":  {"host": "127.0.0.1",               "port": 1025, "tls": False, "label": "ProtonMail (Bridge)"},
        "proton.me":       {"host": "127.0.0.1",               "port": 1025, "tls": False, "label": "ProtonMail (Bridge)"},
    }

    provider = PROVIDERS.get(domain)
    if provider:
        return jsonify({
            "success":  True,
            "detected": True,
            "provider": provider["label"],
            "smtp_host": provider["host"],
            "smtp_port": provider["port"],
            "smtp_use_tls": 1 if provider["tls"] else 0,
            "smtp_user":    email,
        })
    else:
        return jsonify({
            "success":  True,
            "detected": False,
            "provider": "Custom",
            "smtp_host": f"smtp.{domain}",
            "smtp_port": 587,
            "smtp_use_tls": 1,
            "smtp_user":    email,
            "message": "Unknown provider — default settings applied. Adjust in advanced options if needed.",
        })


# ── POST /api/settings/email/test ────────────────────────────────────────────
@app.route("/api/settings/email/test", methods=["POST"])
def api_test_email():
    """
    Send a live test email using the currently saved SMTP credentials.
    Runs in a background thread so the HTTP response returns immediately.
    Returns { success, message } indicating whether the connection succeeded.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    _ensure_email_settings_table()

    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT * FROM email_alert_settings ORDER BY id LIMIT 1")
        cfg = cur.fetchone()
        cur.close()
    except Exception as exc:
        return jsonify({"success": False, "message": f"DB error: {exc}"}), 500

    if not cfg:
        return jsonify({"success": False, "message": "No email settings configured"}), 400

    missing = []
    if not cfg.get("smtp_host"):   missing.append("SMTP Host")
    if not cfg.get("smtp_user"):   missing.append("SMTP Username")
    if not cfg.get("smtp_password"): missing.append("SMTP Password")
    if not cfg.get("alert_recipient"): missing.append("Alert Recipient Email")
    if missing:
        return jsonify({
            "success": False,
            "message": f"Missing required fields: {', '.join(missing)}"
        }), 400

    # Build and send the test message
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "📧 Books & Blooms Café — Test Email"
        msg["From"]    = cfg["smtp_user"]
        msg["To"]      = cfg["alert_recipient"]

        html_body = """
        <div style="font-family:DM Sans,Arial,sans-serif;max-width:520px;margin:0 auto;
                    border:1px solid #e0e0e0;border-radius:10px;overflow:hidden;">
          <div style="background:#1a1a1a;padding:20px 28px;border-bottom:3px solid #c9a961;">
            <h2 style="color:#c9a961;margin:0;font-size:1.3rem;">📚 Books &amp; Blooms Café</h2>
            <p style="color:#aaa;margin:4px 0 0;font-size:0.85rem;">Email Alert System</p>
          </div>
          <div style="padding:28px;">
            <h3 style="color:#1a1a1a;margin-top:0;">✅ Test Email Successful</h3>
            <p style="color:#555;line-height:1.6;">
              Your SMTP configuration is working correctly.<br>
              Low-stock alerts and other notifications will be delivered to this address.
            </p>
            <div style="background:#f5f5f5;border-radius:8px;padding:14px 18px;margin-top:18px;
                        font-size:0.85rem;color:#666;">
              Sent from the Admin Settings page of Books &amp; Blooms Café POS.
            </div>
          </div>
        </div>
        """
        msg.attach(MIMEText(html_body, "html"))

        port = int(cfg.get("smtp_port") or 587)
        use_tls = bool(cfg.get("smtp_use_tls", True))

        if use_tls:
            server = smtplib.SMTP(cfg["smtp_host"], port, timeout=10)
            server.ehlo()
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=10)

        server.login(cfg["smtp_user"], cfg["smtp_password"])
        server.sendmail(cfg["smtp_user"], cfg["alert_recipient"], msg.as_string())
        server.quit()

        return jsonify({"success": True, "message": f"Test email sent to {cfg['alert_recipient']}"})

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "success": False,
            "message": "Authentication failed — check your SMTP username and password (use an App Password for Gmail)"
        }), 400
    except smtplib.SMTPConnectError:
        return jsonify({
            "success": False,
            "message": f"Cannot connect to {cfg['smtp_host']}:{cfg.get('smtp_port', 587)} — verify host and port"
        }), 400
    except Exception as exc:
        app.logger.error(f"[email_settings] test send failed: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── POST /api/settings/email/send-low-stock-alert ────────────────────────────
@app.route("/api/settings/email/send-low-stock-alert", methods=["POST"])
def api_send_low_stock_alert():
    """
    Manually trigger a low-stock alert email right now.
    Fetches the current low-stock items and sends a formatted email report.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    _ensure_email_settings_table()

    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT * FROM email_alert_settings ORDER BY id LIMIT 1")
        cfg = cur.fetchone()
        cur.close()
    except Exception as exc:
        return jsonify({"success": False, "message": f"DB error: {exc}"}), 500

    if not cfg:
        return jsonify({"success": False, "message": "Email settings not configured"}), 400

    if not cfg.get("low_stock_enabled"):
        return jsonify({"success": False, "message": "Low-stock alerts are disabled"}), 400

    missing = []
    if not cfg.get("smtp_host"):      missing.append("SMTP Host")
    if not cfg.get("smtp_user"):      missing.append("SMTP Username")
    if not cfg.get("smtp_password"):  missing.append("SMTP Password")
    if not cfg.get("alert_recipient"): missing.append("Alert Recipient Email")
    if missing:
        return jsonify({
            "success": False,
            "message": f"Incomplete email configuration: {', '.join(missing)}"
        }), 400

    try:
        items = _get_low_stock_items(limit=100)
    except Exception as exc:
        return jsonify({"success": False, "message": f"Could not fetch inventory: {exc}"}), 500

    # Only track ingredients and packaging — finished products are excluded
    supplies = [i for i in items if i["source"] in ("ingredient", "packaging")]

    if not supplies:
        return jsonify({"success": True, "message": "No low-stock ingredients or supplies — everything is sufficiently stocked!"})

    def _build_section_rows(section_items):
        html = ""
        for item in section_items:
            status_color = "#dc3545" if item["status"] == "out" else "#ff9800"
            source_label = {
                "ingredient":  "Ingredient",
                "packaging":   "Packaging",
            }.get(item["source"], item["source"].capitalize())
            html += f"""
        <tr>
          <td style="padding:10px 14px;border-bottom:1px solid #f0f0f0;font-weight:600;">{item['name']}</td>
          <td style="padding:10px 14px;border-bottom:1px solid #f0f0f0;color:#666;">
            {item['category_or_type']}
            <span style="margin-left:5px;background:#f0f0f0;color:#888;
                         padding:1px 7px;border-radius:10px;font-size:0.72rem;">{source_label}</span>
          </td>
          <td style="padding:10px 14px;border-bottom:1px solid #f0f0f0;text-align:center;
                     font-weight:700;color:{status_color};">{item['stock']} {item['unit']}</td>
          <td style="padding:10px 14px;border-bottom:1px solid #f0f0f0;text-align:center;
                     color:#888;">{item['reorder_point']} {item['unit']}</td>
          <td style="padding:10px 14px;border-bottom:1px solid #f0f0f0;text-align:center;">
            <span style="background:{status_color}20;color:{status_color};
                         padding:3px 10px;border-radius:20px;font-size:0.8rem;font-weight:700;">
              {item['status_label']}
            </span>
          </td>
        </tr>"""
        return html

    def _section_header(label, count, icon):
        return f"""
        <tr>
          <td colspan="5" style="padding:10px 14px 6px;background:#f9f9f9;
                                  font-size:0.75rem;font-weight:700;text-transform:uppercase;
                                  letter-spacing:0.8px;color:#888;border-bottom:1px solid #e8e8e8;">
            {icon} {label} <span style="color:#aaa;font-weight:400;">({count} item{'s' if count != 1 else ''})</span>
          </td>
        </tr>"""

    table_head = """
        <table style="width:100%;border-collapse:collapse;font-size:0.88rem;">
          <thead>
            <tr style="background:#f5f5f5;">
              <th style="padding:10px 14px;text-align:left;font-size:0.75rem;text-transform:uppercase;
                         letter-spacing:0.5px;color:#888;border-bottom:2px solid #e0e0e0;">Name</th>
              <th style="padding:10px 14px;text-align:left;font-size:0.75rem;text-transform:uppercase;
                         letter-spacing:0.5px;color:#888;border-bottom:2px solid #e0e0e0;">Category / Type</th>
              <th style="padding:10px 14px;text-align:center;font-size:0.75rem;text-transform:uppercase;
                         letter-spacing:0.5px;color:#888;border-bottom:2px solid #e0e0e0;">Current Stock</th>
              <th style="padding:10px 14px;text-align:center;font-size:0.75rem;text-transform:uppercase;
                         letter-spacing:0.5px;color:#888;border-bottom:2px solid #e0e0e0;">Reorder Point</th>
              <th style="padding:10px 14px;text-align:center;font-size:0.75rem;text-transform:uppercase;
                         letter-spacing:0.5px;color:#888;border-bottom:2px solid #e0e0e0;">Status</th>
            </tr>
          </thead>
          <tbody>"""

    rows_html = _section_header("Ingredients &amp; Supplies", len(supplies), "📦")
    rows_html += _build_section_rows(supplies)

    table_html = table_head + rows_html + "</tbody></table>"

    now_str   = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    out_count = sum(1 for i in supplies if i["status"] == "out")
    low_count = sum(1 for i in supplies if i["status"] == "low")

    html_body = f"""
    <div style="font-family:DM Sans,Arial,sans-serif;max-width:720px;margin:0 auto;
                border:1px solid #e0e0e0;border-radius:10px;overflow:hidden;">
      <div style="background:#1a1a1a;padding:20px 28px;border-bottom:3px solid #c9a961;">
        <h2 style="color:#c9a961;margin:0;font-size:1.3rem;">📚 Books &amp; Blooms Café</h2>
        <p style="color:#aaa;margin:4px 0 0;font-size:0.85rem;">Inventory Alert System · {now_str}</p>
      </div>
      <div style="padding:24px 28px;">
        <h3 style="color:#1a1a1a;margin-top:0;">📦 Low-Stock Alert — Ingredients &amp; Supplies</h3>
        <p style="color:#555;line-height:1.6;margin-bottom:8px;">
          <strong>{len(supplies)} ingredient/supply item(s)</strong> require immediate attention —
          <span style="color:#dc3545;font-weight:700;">{out_count} out of stock</span>,
          <span style="color:#ff9800;font-weight:700;">{low_count} running low</span>.
        </p>
        <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
          <span style="background:#e8f5e9;color:#2e7d32;padding:4px 12px;border-radius:20px;
                       font-size:0.82rem;font-weight:700;">
            📦 {len(supplies)} ingredient / suppl{'ies' if len(supplies) != 1 else 'y'}
          </span>
        </div>
        {table_html}
        <div style="background:#fff8e1;border:1px solid #ffe082;border-radius:8px;
                    padding:14px 18px;margin-top:24px;font-size:0.85rem;color:#7c5e00;">
          ⚡ Please restock these items as soon as possible to avoid service interruption.
        </div>
      </div>
      <div style="background:#f5f5f5;padding:14px 28px;font-size:0.78rem;color:#aaa;
                  border-top:1px solid #e0e0e0;text-align:center;">
        This alert was sent from Books &amp; Blooms Café POS · Admin Settings
      </div>
    </div>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"📦 Low-Stock Alert — {len(supplies)} ingredient/supply item(s) need restocking"
        msg["From"]    = cfg["smtp_user"]
        msg["To"]      = cfg["alert_recipient"]
        msg.attach(MIMEText(html_body, "html"))

        port    = int(cfg.get("smtp_port") or 587)
        use_tls = bool(cfg.get("smtp_use_tls", True))

        if use_tls:
            server = smtplib.SMTP(cfg["smtp_host"], port, timeout=10)
            server.ehlo()
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=10)

        server.login(cfg["smtp_user"], cfg["smtp_password"])
        server.sendmail(cfg["smtp_user"], cfg["alert_recipient"], msg.as_string())
        server.quit()

        return jsonify({
            "success": True,
            "message": (
                f"Alert sent to {cfg['alert_recipient']} — "
                f"{len(supplies)} ingredient/supply item(s) reported"
            ),
            "items_count": len(supplies),
            "supplies_count": len(supplies),
        })

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "success": False,
            "message": "SMTP authentication failed — check username/password (use an App Password for Gmail)"
        }), 400
    except Exception as exc:
        app.logger.error(f"[email_settings] low-stock send failed: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         CASHIER DASHBOARD                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/cashier_dashboard")
def cashier_dashboard():
    if "employee_id" not in session or session.get("role") != "cashier":
        return redirect(url_for("login"))

    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT full_name, username, role, contact_number, last_login FROM employees WHERE employee_id=%s",
        (session["employee_id"],),
    )
    employee = _dec_emp(cur.fetchone())
    cur.close()

    return render_template("cashier/cashier_dashboard.html", employee=employee)


@app.route("/cashier_transactions")
def cashier_transactions():
    if "employee_id" not in session or session.get("role") != "cashier":
        return redirect(url_for("login"))

    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT full_name, username, role, contact_number, last_login FROM employees WHERE employee_id=%s",
        (session["employee_id"],),
    )
    employee = _dec_emp(cur.fetchone())
    cur.close()

    return render_template("cashier/transaction.html", employee=employee)


@app.route("/cashier_attendance")
def cashier_attendance():
    """Cashier-only attendance page — clock-in/out and own history only."""
    if "employee_id" not in session or session.get("role") != "cashier":
        return redirect(url_for("login"))
    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT employee_id, full_name, role, hourly_rate FROM employees WHERE employee_id=%s",
        (session["employee_id"],),
    )
    employee = _dec_emp(cur.fetchone())
    cur.close()
    return render_template("cashier/cashier_attendance.html", employee=employee)


# ── Admin Sales page ──────────────────────────────────────────────────────────


@app.route("/admin_sales")
def admin_sales():
    """Admin sales overview — transaction history + per-cashier shift reports."""
    if not is_admin():
        return redirect(url_for("login"))

    full_name = session.get("full_name")
    if not full_name:
        try:
            cur = mysql.connection.cursor(DictCursor)
            if session.get("role") == "admin":
                cur.execute(
                    "SELECT full_name FROM admins WHERE admin_id=%s",
                    (session["admin_id"],),
                )
                user = _dec_adm(cur.fetchone())
            else:
                cur.execute(
                    "SELECT full_name FROM employees WHERE employee_id=%s",
                    (session["employee_id"],),
                )
                user = _dec_emp(cur.fetchone())
            full_name = (
                user["full_name"] if user else session["role"].capitalize()
            ).strip()
            cur.close()
        except Exception:
            full_name = "Admin"

    return render_template("admin_sales.html", full_name=full_name)


@app.route("/product_management")
def product_management():
    """Render the admin product management page."""
    if not is_admin():
        return redirect(url_for("login"))
    full_name = session.get("full_name") or "Admin"
    return render_template("product_management.html", full_name=full_name)


# ── POST /api/products/upload_image ───────────────────────────────────────────


@app.route("/api/products/upload_image", methods=["POST"])
def api_products_upload_image():
    """
    Upload a product image (multipart/form-data, field 'image').
    Optional form field 'product_id' — if provided, also updates DB row.
    Returns { success, image_url }.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    if "image" not in request.files:
        return jsonify({"success": False, "message": "No image file provided"}), 400

    file = request.files["image"]
    if not file or file.filename == "":
        return jsonify({"success": False, "message": "No file selected"}), 400

    if not _allowed_image(file.filename):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "File type not allowed. Use JPG, PNG, WEBP or GIF.",
                }
            ),
            400,
        )

    # Enforce size limit
    file.seek(0, 2)
    size_bytes = file.tell()
    file.seek(0)
    if size_bytes > MAX_PRODUCT_IMAGE_MB * 1024 * 1024:
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Image too large (max {MAX_PRODUCT_IMAGE_MB} MB)",
                }
            ),
            400,
        )

    try:
        ext = secure_filename(file.filename).rsplit(".", 1)[-1].lower()
        uid = secrets.token_hex(12)
        filename = f"prod_{uid}.{ext}"
        save_path = os.path.join(PRODUCT_IMAGE_FOLDER, filename)
        file.save(save_path)
        image_url = f"/static/product_images/{filename}"

        # Optionally persist to DB and clean up old image
        product_id = request.form.get("product_id")
        if product_id:
            try:
                cur2 = mysql.connection.cursor(DictCursor)
                cur2.execute(
                    "SELECT image_url FROM products WHERE product_id=%s",
                    (int(product_id),),
                )
                row = cur2.fetchone()
                cur2.close()
                if row and row.get("image_url"):
                    old_path = row["image_url"].lstrip("/")
                    if os.path.exists(old_path):
                        try:
                            os.remove(old_path)
                        except OSError:
                            pass

                cur3 = mysql.connection.cursor()
                cur3.execute(
                    "UPDATE products SET image_url=%s WHERE product_id=%s",
                    (image_url, int(product_id)),
                )
                mysql.connection.commit()
                cur3.close()
            except Exception as db_exc:
                app.logger.warning(f"[products] image DB update failed: {db_exc}")

        return jsonify({"success": True, "image_url": image_url})
    except Exception as exc:
        app.logger.error(f"[products] upload_image: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/products/pos ─────────────────────────────────────────────────────


@app.route("/api/products/pos", methods=["GET"])
def api_products_pos():
    """
    POS endpoint for cashiers and admins.
    Returns active products with images + categories for the POS dashboard.
    """
    if "employee_id" not in session and not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        cur = mysql.connection.cursor(DictCursor)

        # Only categories that actually have products
        cur.execute(
            """
            SELECT c.category_id, c.name,
                   COUNT(p.product_id) AS product_count
            FROM   categories c
            LEFT   JOIN products p
                   ON p.category_id = c.category_id AND p.is_active = 1
            GROUP  BY c.category_id
            HAVING product_count > 0
            ORDER  BY c.name
        """
        )
        categories = [
            {
                "category_id": c["category_id"],
                "name": c["name"],
                "product_count": int(c["product_count"]),
            }
            for c in cur.fetchall()
        ]

        # All active products
        cur.execute(
            """
            SELECT p.product_id, p.name, p.description,
                   p.image_url, p.icon, p.cup_eligible, p.price, p.stock, p.unit,
                   c.category_id, c.name AS category_name
            FROM   products p
            LEFT   JOIN categories c ON c.category_id = p.category_id
            WHERE  p.is_active = 1
            ORDER  BY c.name, p.name
        """
        )
        items = [
            {
                "product_id": r["product_id"],
                "name": r["name"],
                "description": r["description"] or "",
                "image_url": r["image_url"] or "",
                "icon": r["icon"] or "📦",
                "cup_eligible": bool(r.get("cup_eligible", 0)),
                "price": float(r["price"]),
                "stock": int(r["stock"]),
                "unit": r["unit"],
                "category_id": r["category_id"],
                "category_name": r["category_name"] or "Other",
            }
            for r in cur.fetchall()
        ]
        cur.close()
        return jsonify(
            {
                "success": True,
                "items": items,
                "products": items,
                "categories": categories,
            }
        )
    except Exception as exc:
        app.logger.error(f"[products] api_products_pos: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── PUT /api/inventory/categories/<id> ────────────────────────────────────────


@app.route("/api/inventory/categories/<int:category_id>", methods=["PUT"])
def api_inventory_categories_update(category_id):
    """Update an existing category's name."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()

    if not name:
        return jsonify({"success": False, "message": "Category name is required"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE categories SET name=%s WHERE category_id=%s", (name, category_id)
        )
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return jsonify({"success": False, "message": "Category not found"}), 404
        return jsonify({"success": True, "message": f'Category "{name}" updated'})
    except Exception as exc:
        app.logger.error(f"[inventory] update category #{category_id}: {exc}")
        return (
            jsonify({"success": False, "message": "Name already exists or DB error"}),
            400,
        )


# ── DELETE /api/inventory/categories/<id> ─────────────────────────────────────


@app.route("/api/inventory/categories/<int:category_id>", methods=["DELETE"])
def api_inventory_categories_delete(category_id):
    """Delete a category. Products in this category will have their category_id set to NULL."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        cur = mysql.connection.cursor(DictCursor)
        # Check category exists
        cur.execute(
            "SELECT name FROM categories WHERE category_id = %s", (category_id,)
        )
        row = cur.fetchone()
        if not row:
            cur.close()
            return jsonify({"success": False, "message": "Category not found"}), 404
        cat_name = row["name"]
        # Unassign products from this category
        cur.execute(
            "UPDATE products SET category_id = NULL WHERE category_id = %s",
            (category_id,),
        )
        # Delete the category
        cur.execute("DELETE FROM categories WHERE category_id = %s", (category_id,))
        mysql.connection.commit()
        cur.close()
        return jsonify({"success": True, "message": f'Category "{cat_name}" deleted'})
    except Exception as exc:
        app.logger.error(f"[inventory] delete category #{category_id}: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


@app.route("/api/my_attendance", methods=["GET"])
def api_my_attendance():
    """
    Returns attendance records scoped strictly to the logged-in cashier.
    Accepts ?date=YYYY-MM-DD for single day, or ?range_start=&range_end= for a period.
    """
    if "employee_id" not in session or session.get("role") != "cashier":
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    employee_id = session["employee_id"]
    date_str = request.args.get("date", "")
    range_start = request.args.get("range_start", "")
    range_end = request.args.get("range_end", "")
    cur = mysql.connection.cursor(DictCursor)

    BASE_SQL = """
        SELECT
            a.attendance_id,
            DATE_FORMAT(a.attendance_date, '%%Y-%%m-%%d') AS attendance_date,
            a.shift_type,
            DATE_FORMAT(a.clock_in,  '%%H:%%i:%%s') AS clock_in,
            DATE_FORMAT(a.clock_out, '%%H:%%i:%%s') AS clock_out,
            CASE WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                 THEN ROUND(TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out)/60, 2)
                 ELSE NULL END AS hours_worked,
            CASE WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                      AND TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) >= 480
                 THEN 'YES' ELSE 'NO' END AS fulfill_working_hours,
            COALESCE(NULLIF(a.daily_earnings,0),
                CASE WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                THEN ROUND(TIMESTAMPDIFF(MINUTE,a.clock_in,a.clock_out)/60.0
                           * COALESCE(e.hourly_rate,0), 2)
                ELSE NULL END) AS daily_pay
        FROM attendance a
        JOIN employees e ON e.employee_id = a.employee_id
        WHERE a.employee_id = %s
    """

    if range_start and range_end:
        try:
            datetime.strptime(range_start, "%Y-%m-%d")
            datetime.strptime(range_end, "%Y-%m-%d")
        except ValueError:
            cur.close()
            return jsonify({"success": False, "message": "Invalid date format"}), 400
        cur.execute(
            BASE_SQL
            + " AND a.attendance_date BETWEEN %s AND %s ORDER BY a.attendance_date DESC, a.clock_in DESC",
            (employee_id, range_start, range_end),
        )
        rows = cur.fetchall()
        cur.close()
        total_hours = round(
            sum(float(r["hours_worked"]) for r in rows if r.get("hours_worked")), 2
        )
        return jsonify(
            {
                "success": True,
                "records": rows,
                "total_hours": total_hours,
                "range_start": range_start,
                "range_end": range_end,
            }
        )
    else:
        dt = datetime.now().date()
        if date_str:
            try:
                dt = datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                cur.close()
                return (
                    jsonify({"success": False, "message": "Invalid date format"}),
                    400,
                )
        cur.execute(
            BASE_SQL + " AND a.attendance_date = %s ORDER BY a.clock_in DESC",
            (employee_id, dt),
        )
        rows = cur.fetchall()
        cur.close()
        total_hours = round(
            sum(float(r["hours_worked"]) for r in rows if r.get("hours_worked")), 2
        )
        return jsonify(
            {
                "success": True,
                "date": str(dt),
                "records": rows,
                "total_hours": total_hours,
            }
        )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                            LOGOUT                                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin/unlock_account", methods=["POST"])
def unlock_account():
    """Clear a login lockout for the given username + role."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    role = (data.get("role") or "").strip()

    if not username or role not in ("admin", "manager", "cashier"):
        return (
            jsonify(
                {"success": False, "message": "username and valid role are required"}
            ),
            400,
        )

    u_hash = aes_username_hash(username)
    clear_failed_attempts(u_hash, role)
    app.logger.info(
        f"[lockout] Admin {session.get('admin_id') or session.get('employee_id')} "
        f"manually unlocked {role!r} account for username_hash={u_hash[:12]}…"
    )
    return jsonify({"success": True, "message": f"Lockout cleared for {role} account."})


@app.route("/admin/lockout_status", methods=["GET"])
def lockout_status():
    """
    Return the current lockout state for a username + role.
    Query params: ?username=...&role=...
    Useful for the admin UI to check status before deciding to unlock.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    username = (request.args.get("username") or "").strip()
    role = (request.args.get("role") or "").strip()

    if not username or role not in ("admin", "manager", "cashier"):
        return (
            jsonify(
                {"success": False, "message": "username and valid role are required"}
            ),
            400,
        )

    u_hash = aes_username_hash(username)
    state = check_lockout(u_hash, role)
    return jsonify({"success": True, **state})


# ── Secret token that must be submitted with the form ─────────────────────────
# IMPORTANT: Replace this with a long, random string (e.g. from os.urandom).
# Keep this value out of version control (use an environment variable in prod).
ADMIN_SETUP_TOKEN = os.environ.get(
    "ADMIN_SETUP_TOKEN", "change-me-before-deploying-abc123!"
)


@app.route("/setup/create-admin-xK9mQ2", methods=["GET", "POST"])
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
    if request.method == "POST":
        submitted_token = request.form.get("setup_token", "").strip()
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # ── 1. Validate secret token ─────────────────────────────────────────
        if submitted_token != ADMIN_SETUP_TOKEN:
            flash("Invalid setup token. Access denied.", "error")
            return render_template("create_admin.html")

        # ── 2. Validate fields ───────────────────────────────────────────────
        if not all([full_name, username, password, confirm_password]):
            flash("All fields are required.", "error")
            return render_template("create_admin.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("create_admin.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("create_admin.html")

        # ── 3. Check username uniqueness via hash ────────────────────────────
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            "SELECT admin_id FROM admins WHERE username_hash = %s LIMIT 1",
            (aes_username_hash(username),),
        )
        existing = cur.fetchone()

        if existing:
            cur.close()
            flash("That username is already taken. Choose another.", "error")
            return render_template("create_admin.html")

        # ── 4. Insert new admin (AES-256 encrypted + bcrypt hashed) ─────────
        try:
            cur.execute(
                "INSERT INTO admins (full_name, username, username_hash, password, password_hash) VALUES (%s, %s, %s, %s, %s)",
                (
                    aes_encrypt(full_name),
                    aes_encrypt(username),
                    aes_username_hash(username),
                    aes_encrypt(password),
                    hash_password(password),
                ),
            )
            mysql.connection.commit()
            cur.close()
            flash(
                f'Admin account "{username}" created successfully. You may now log in.',
                "success",
            )
        except Exception as e:
            cur.close()
            flash(f"Database error: {e}", "error")

        return render_template("create_admin.html")

    # GET ─ just render the form
    return render_template("create_admin.html")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                            ENTRY POINT                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def _is_enc(value: str) -> bool:
    """Return True if value is already AES-encrypted (successfully decryptable)."""
    if not value:
        return False
    try:
        raw = base64.b64decode(value)
        if len(raw) < 32:
            return False
        unpad(
            AES.new(AES_KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), AES.block_size
        )
        return True
    except Exception:
        return False


def run_auto_migration():
    """
    Runs once on first request.  Every step is independently guarded so a
    failure in any earlier step cannot prevent later steps from running.

    Steps 1-4 operate on the employees/admins tables (column widening +
    AES encryption of any remaining plaintext rows).  Steps 5-10 are
    independent DDL / table-creation tasks that must always run regardless
    of whether steps 1-4 succeeded.
    """
    # ── STEPS 1-4: username_hash columns, column widening, AES migration ──────
    # These touch employees/admins — wrapped together because they share a cursor,
    # but isolated from steps 5-10 so a missing table cannot kill inventory setup.
    try:
        conn = mysql.connection
        cur = conn.cursor(DictCursor)

        # STEP 1: add username_hash columns
        for tbl in ("employees", "admins"):
            try:
                cur.execute(
                    f"ALTER TABLE `{tbl}` "
                    f"ADD COLUMN `username_hash` VARCHAR(64) DEFAULT NULL"
                )
                conn.commit()
                app.logger.info(f"[migration] Added username_hash to {tbl}")
            except Exception:
                pass  # column already exists — expected on re-runs

        # STEP 2: widen narrow columns before writing ciphertext
        # AES-256-CBC base64(IV+ciphertext) is always >= 44 chars.
        # VARCHAR(20) / VARCHAR(50) silently truncate the blob.
        widen = [
            ("employees", "contact_number", "VARCHAR(255)"),
            ("employees", "username", "VARCHAR(255)"),
            ("employees", "full_name", "VARCHAR(255)"),
            ("employees", "password", "VARCHAR(255)"),
            ("admins", "username", "VARCHAR(255)"),
            ("admins", "full_name", "VARCHAR(255)"),
            ("admins", "password", "VARCHAR(255)"),
        ]
        for tbl, col, typ in widen:
            try:
                cur.execute(
                    f"ALTER TABLE `{tbl}` MODIFY COLUMN `{col}` {typ} NOT NULL DEFAULT ''"
                )
                conn.commit()
                app.logger.info(f"[migration] Widened {tbl}.{col} -> {typ}")
            except Exception as e:
                app.logger.debug(f"[migration] Widen {tbl}.{col} skipped: {e}")

        # STEPS 3 & 4: repair truncated blobs and encrypt plaintext rows
        cur.execute(
            "SELECT employee_id, username, full_name, password, contact_number "
            "FROM employees"
        )
        for row in cur.fetchall():
            upd = {}
            for f in ("username", "full_name", "password", "contact_number"):
                v = row.get(f)
                if not v:
                    continue
                s = str(v).strip()
                if _is_enc(s):
                    continue
                import re as _re

                if _re.fullmatch(r"[A-Za-z0-9+/=]+", s) and 16 <= len(s) < 44:
                    upd[f] = ""
                    app.logger.warning(
                        f"[migration] Cleared truncated ciphertext in "
                        f"employee #{row['employee_id']}.{f}"
                    )
                else:
                    upd[f] = aes_encrypt(s)

            raw_u = row.get("username", "") or ""
            plain_u = aes_decrypt(str(raw_u).strip()) if raw_u else ""
            if raw_u and not _is_enc(str(raw_u).strip()):
                upd["username_hash"] = aes_username_hash(str(raw_u).strip())
            elif plain_u and not row.get("username_hash"):
                upd["username_hash"] = aes_username_hash(plain_u)

            if upd:
                sql = (
                    "UPDATE employees SET "
                    + ", ".join(f"`{k}`=%s" for k in upd)
                    + " WHERE employee_id=%s"
                )
                cur.execute(sql, list(upd.values()) + [row["employee_id"]])
                app.logger.info(
                    f"[migration] Fixed employee #{row['employee_id']} fields={list(upd.keys())}"
                )

        cur.execute("SELECT admin_id, username, full_name, password FROM admins")
        for row in cur.fetchall():
            upd = {}
            for f in ("username", "full_name", "password"):
                v = row.get(f)
                if not v:
                    continue
                s = str(v).strip()
                if _is_enc(s):
                    continue
                import re as _re

                if _re.fullmatch(r"[A-Za-z0-9+/=]+", s) and 16 <= len(s) < 44:
                    upd[f] = ""
                    app.logger.warning(
                        f"[migration] Cleared truncated ciphertext in "
                        f"admin #{row['admin_id']}.{f}"
                    )
                else:
                    upd[f] = aes_encrypt(s)

            raw_u = row.get("username", "") or ""
            if raw_u and not _is_enc(str(raw_u).strip()):
                upd["username_hash"] = aes_username_hash(str(raw_u).strip())

            if upd:
                sql = (
                    "UPDATE admins SET "
                    + ", ".join(f"`{k}`=%s" for k in upd)
                    + " WHERE admin_id=%s"
                )
                cur.execute(sql, list(upd.values()) + [row["admin_id"]])
                app.logger.info(
                    f"[migration] Fixed admin #{row['admin_id']} fields={list(upd.keys())}"
                )

        conn.commit()
        cur.close()
        app.logger.info("[migration] Steps 1-4 complete.")

    except Exception as exc:
        app.logger.error(f"[migration] Steps 1-4 failed (non-fatal): {exc}")

    # ── STEP 5: password_hash columns + bcrypt backfill ───────────────────────
    try:
        _widen_password_hash_columns()
        _backfill_bcrypt_hashes()
    except Exception as exc:
        app.logger.error(f"[migration] Step 5 (bcrypt) failed (non-fatal): {exc}")

    # ── STEP 6: login_attempts + face_mismatch_log tables ─────────────────────
    try:
        _ensure_lockout_table()
    except Exception as exc:
        app.logger.error(
            f"[migration] Step 6 (lockout table) failed (non-fatal): {exc}"
        )

    # ── STEP 7: widen face_model_path VARCHAR(255) → MEDIUMTEXT ──────────────
    try:
        _widen_face_model_path()
    except Exception as exc:
        app.logger.error(
            f"[migration] Step 7 (face_model_path) failed (non-fatal): {exc}"
        )

    # ── STEP 8: employees_trash table + migrate inactive rows ─────────────────
    try:
        _ensure_trash_table()
    except Exception as exc:
        app.logger.error(f"[migration] Step 8 (trash table) failed (non-fatal): {exc}")

    # ── STEP 9: payroll tables ────────────────────────────────────────────────
    try:
        _ensure_payroll_tables()
    except Exception as exc:
        app.logger.error(
            f"[migration] Step 9 (payroll tables) failed (non-fatal): {exc}"
        )

    # ── STEP 10: inventory tables (categories + products) ────────────────────
    # This MUST always run — it creates the tables the inventory page depends on.
    try:
        _ensure_inventory_tables()
    except Exception as exc:
        app.logger.error(f"[migration] Step 10 (inventory tables) failed: {exc}")

    # ── STEP 11: sales tables (transactions + transaction_items) ─────────────
    try:
        _ensure_sales_tables()
    except Exception as exc:
        app.logger.error(f"[migration] Step 11 (sales tables) failed: {exc}")

    # ── STEP 12: inv_items + inv_log tables ───────────────────────────────────
    try:
        _ensure_inv_tables()
    except Exception as exc:
        app.logger.error(f"[migration] Step 12 (inv_items tables) failed: {exc}")

    # ── STEP 13: employee_applications table ──────────────────────────────────
    try:
        _ensure_employee_applications_table()
    except Exception as exc:
        app.logger.error(f"[migration] Step 13 (employee_applications) failed: {exc}")

    # ── STEP 14: add cup_eligible column to products ─────────────────────────
    try:
        _ensure_cup_eligible_column()
    except Exception as exc:
        app.logger.error(f"[migration] Step 14 (cup_eligible) failed: {exc}")

    # ── STEP 15: add VAT / discount_type columns to transactions ─────────────
    try:
        _ensure_vat_columns()
    except Exception as exc:
        app.logger.error(f"[migration] Step 15 (VAT columns) failed: {exc}")

    app.logger.info("[migration] run_auto_migration complete.")


def _ensure_vat_columns():
    """
    Idempotent: add discount_type, net_sales, vat_amount columns to
    `transactions` if they are not already present.

    discount_type  — 'none' | 'senior' | 'pwd' | 'manual'
    net_sales      — VAT-exclusive amount AFTER discount  (total / 1.12)
    vat_amount     — 12% VAT component                   (net_sales * 0.12)
    """
    try:
        conn = mysql.connection
        cur = conn.cursor()
        for col, defn in [
            (
                "discount_type",
                "ENUM('none','senior','pwd','manual') NOT NULL DEFAULT 'none'",
            ),
            ("net_sales", "DECIMAL(12,2) NOT NULL DEFAULT 0.00"),
            ("vat_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0.00"),
        ]:
            try:
                cur.execute(f"ALTER TABLE `transactions` ADD COLUMN `{col}` {defn}")
                conn.commit()
                app.logger.info(f"[migration] Added transactions.{col}")
            except Exception:
                pass  # column already exists
        # Back-fill existing rows: compute net_sales & vat_amount from total_amount
        cur.execute(
            """
            UPDATE transactions
               SET net_sales  = ROUND(total_amount / 1.12, 2),
                   vat_amount = ROUND(total_amount / 1.12 * 0.12, 2)
             WHERE vat_amount = 0 AND total_amount > 0
        """
        )
        conn.commit()
        cur.close()
        app.logger.info("[migration] VAT columns ensured on transactions")
    except Exception as exc:
        app.logger.error(f"[migration] _ensure_vat_columns: {exc}")


def _ensure_cup_eligible_column():
    """
    Add cup_eligible TINYINT(1) to products (idempotent).
    cup_eligible = 1  ->  cashier prompted for 8oz / 12oz / 16oz at POS.
    cup_eligible = 0  ->  no size prompt.
    Back-fills products whose unit was 8oz / 12oz / 16oz / cup.
    """
    try:
        conn = mysql.connection
        cur = conn.cursor(DictCursor)
        try:
            cur.execute(
                "ALTER TABLE `products` "
                "ADD COLUMN `cup_eligible` TINYINT(1) NOT NULL DEFAULT 0"
            )
            conn.commit()
            app.logger.info("[migration] Added cup_eligible column to products")
        except Exception:
            pass  # column already exists — harmless
        # Hide legacy "cup products" that were accidentally created when cup
        # size was stored as a product.unit — these are packaging rows that
        # ended up in the products table and should not show in the POS.
        # They are identified by unit IN ('8oz','12oz','16oz') AND price=0.
        cur.execute(
            "UPDATE products SET is_active = 0 "
            "WHERE unit IN ('8oz','12oz','16oz') AND price = 0 AND is_active = 1"
        )
        # Real drink products whose unit was set to a cup size: mark cup_eligible,
        # reset unit to 'pcs' so they show on POS without a fixed size.
        cur.execute(
            "UPDATE products SET cup_eligible = 1, unit = 'pcs' "
            "WHERE unit IN ('8oz','12oz','16oz','cup') AND price > 0 AND cup_eligible = 0"
        )
        conn.commit()
        cur.close()
        app.logger.info("[migration] cup_eligible backfill complete")
    except Exception as exc:
        app.logger.error(f"[migration] _ensure_cup_eligible_column: {exc}")


def _ensure_payroll_tables():
    """
    Idempotent DDL bootstrap — all ALTER TABLE calls skip silently if columns
    already exist (schema is already up-to-date in the current DB version).
    """
    try:
        conn = mysql.connection
        cur = conn.cursor()

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
            ("hours_worked", "DECIMAL(10,4) NOT NULL DEFAULT 0.0000"),
            ("hourly_rate_snapshot", "DECIMAL(10,2) NOT NULL DEFAULT 0.00"),
            ("daily_earnings", "DECIMAL(10,2) NOT NULL DEFAULT 0.00"),
            ("pay_period_start", "DATE DEFAULT NULL"),
            ("pay_period_end", "DATE DEFAULT NULL"),
            ("daily_pay", "DECIMAL(10,2) DEFAULT NULL"),
        ]:
            try:
                cur.execute(f"ALTER TABLE `attendance` ADD COLUMN `{col}` {defn}")
                conn.commit()
                app.logger.info(f"[payroll] Added attendance.{col}")
            except Exception:
                pass

        # ── payroll_periods — one row per (employee × pay-period) ────────────
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS `payroll_periods` (
                `payroll_id`   INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
                `employee_id`  INT           NOT NULL,
                `period_start` DATE          NOT NULL,
                `period_end`   DATE          NOT NULL,
                `total_hours`  DECIMAL(8,2)  NOT NULL DEFAULT 0.00,
                `total_pay`    DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                `days_worked`  SMALLINT      NOT NULL DEFAULT 0,
                `status`       ENUM('draft','finalized') NOT NULL DEFAULT 'draft',
                `generated_at` DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `finalized_at` DATETIME      DEFAULT NULL,
                `notes`        TEXT          DEFAULT NULL,
                UNIQUE KEY `uq_emp_period` (`employee_id`, `period_start`),
                INDEX `idx_period_start` (`period_start`),
                INDEX `idx_employee_id`  (`employee_id`),
                CONSTRAINT `payroll_periods_ibfk_1`
                    FOREIGN KEY (`employee_id`) REFERENCES `employees`(`employee_id`) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """
        )
        # Patch existing tables: add unique key if missing (idempotent)
        try:
            cur.execute(
                "SELECT COUNT(*) AS c FROM information_schema.STATISTICS "
                "WHERE table_schema=DATABASE() AND table_name='payroll_periods' "
                "AND index_name='uq_emp_period'"
            )
            if cur.fetchone()["c"] == 0:
                cur.execute(
                    "ALTER TABLE payroll_periods "
                    "ADD UNIQUE KEY uq_emp_period (employee_id, period_start)"
                )
                app.logger.info("[payroll] Added uq_emp_period unique key")
        except Exception as patch_exc:
            app.logger.warning(f"[payroll] uq_emp_period patch skipped: {patch_exc}")

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
        cur.execute(
            """
            SELECT a.clock_in, a.clock_out, a.attendance_date,
                   COALESCE(e.hourly_rate, 0) AS hourly_rate
            FROM   attendance a
            JOIN   employees  e ON e.employee_id = a.employee_id
            WHERE  a.attendance_id = %s
        """,
            (attendance_id,),
        )
        row = cur.fetchone()
        if not row or not row.get("clock_out"):
            cur.close()
            return

        delta_min = (row["clock_out"] - row["clock_in"]).total_seconds() / 60.0
        hours = round(delta_min / 60.0, 4)
        rate = float(row["hourly_rate"])
        earnings = round(hours * rate, 2)

        d = row["attendance_date"]
        if d.day <= 15:
            ps, pe = d.replace(day=1), d.replace(day=15)
        else:
            last = _cal.monthrange(d.year, d.month)[1]
            ps, pe = d.replace(day=16), d.replace(day=last)

        cur.execute(
            """
            UPDATE attendance
               SET hours_worked         = %s,
                   hourly_rate_snapshot = %s,
                   daily_earnings       = %s,
                   pay_period_start     = %s,
                   pay_period_end       = %s
             WHERE attendance_id = %s
        """,
            (hours, rate, earnings, ps, pe, attendance_id),
        )
        conn.commit()
        cur.close()
        app.logger.info(
            f"[payroll] att#{attendance_id}: {hours:.2f}h x P{rate:.2f} = P{earnings:.2f} ({ps}->{pe})"
        )
    except Exception as exc:
        app.logger.error(
            f"[payroll] _store_clock_out_pay failed att#{attendance_id}: {exc}"
        )


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


@app.route("/payroll")
def payroll():
    """Render the payroll dashboard page."""
    if not is_admin():
        return redirect(url_for("login"))
    cur = mysql.connection.cursor(DictCursor)
    if session.get("role") == "admin" and "admin_id" in session:
        cur.execute(
            "SELECT full_name FROM admins WHERE admin_id=%s", (session["admin_id"],)
        )
        user = _dec_adm(cur.fetchone())
    else:
        cur.execute(
            "SELECT full_name FROM employees WHERE employee_id=%s",
            (session["employee_id"],),
        )
        user = _dec_emp(cur.fetchone())
    full_name = user["full_name"] if user else session.get("full_name", "Admin")
    cur.close()
    return render_template("payroll.html", full_name=full_name)


@app.route("/api/payroll/employees", methods=["GET"])
def api_payroll_employees():
    """
    Return all active employees with their hourly_rate for the payroll UI.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        "SELECT employee_id, full_name, role, hourly_rate "
        "FROM employees WHERE employment_status='active' ORDER BY full_name"
    )
    rows = cur.fetchall()
    cur.close()
    for row in rows:
        if row.get("full_name"):
            row["full_name"] = aes_decrypt(row["full_name"]) or row["full_name"]
        row["hourly_rate"] = float(row["hourly_rate"] or 0)
    return jsonify({"success": True, "employees": rows})


@app.route("/api/payroll/update_rate", methods=["POST"])
def api_payroll_update_rate():
    """Admin: update an employee's hourly_rate."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    employee_id = data.get("employee_id")
    try:
        rate = float(data.get("hourly_rate", 0))
        if rate < 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid hourly rate"}), 400
    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE employees SET hourly_rate=%s WHERE employee_id=%s", (rate, employee_id)
    )
    mysql.connection.commit()
    cur.close()
    return jsonify({"success": True, "message": "Hourly rate updated"})


@app.route("/api/payroll/daily", methods=["GET"])
def api_payroll_daily():
    """
    Return daily pay breakdown for each employee for a given date.
    Calculates: hours_worked × hourly_rate = daily_pay.
    Also persists daily_pay back to the attendance row.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    date_str = request.args.get("date")
    try:
        from datetime import date as _date

        dt = (
            datetime.strptime(date_str, "%Y-%m-%d").date()
            if date_str
            else _date.today()
        )
    except ValueError:
        return jsonify({"success": False, "message": "Invalid date"}), 400

    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        """
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
    """,
        (dt,),
    )
    rows = cur.fetchall()

    result = []
    for row in rows:
        name = aes_decrypt(row["full_name"]) if row.get("full_name") else ""
        hours = (
            float(row["hours_worked"] or 0) if row["hours_worked"] is not None else None
        )
        rate = float(row["hourly_rate"] or 0)
        pay = (
            float(row["daily_earnings"] or 0)
            if row["daily_earnings"] is not None
            else None
        )
        result.append(
            {
                "attendance_id": row["attendance_id"],
                "employee_id": row["employee_id"],
                "full_name": name,
                "role": row["role"],
                "shift_type": row["shift_type"],
                "clock_in": row["clock_in"],
                "clock_out": row["clock_out"],
                "hours_worked": round(hours, 2) if hours is not None else None,
                "hourly_rate": rate,
                "daily_pay": round(pay, 2) if pay is not None else None,
                "pay_period_start": (
                    str(row["pay_period_start"]) if row["pay_period_start"] else None
                ),
                "pay_period_end": (
                    str(row["pay_period_end"]) if row["pay_period_end"] else None
                ),
            }
        )

    cur.close()
    return jsonify({"success": True, "date": str(dt), "records": result})


@app.route("/api/payroll/period", methods=["GET"])
def api_payroll_period():
    """
    Return payroll summary for a 15-day period.

    Query params:
        period_start  — YYYY-MM-DD  (auto-computed if omitted)
        period_end    — YYYY-MM-DD
        employee_id   — optional filter
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    from datetime import date as _date, timedelta
    import calendar as _cal

    # ── Resolve period bounds ────────────────────────────────────────────────
    ps = request.args.get("period_start")
    pe = request.args.get("period_end")
    try:
        if ps and pe:
            period_start = datetime.strptime(ps, "%Y-%m-%d").date()
            period_end = datetime.strptime(pe, "%Y-%m-%d").date()
        else:
            period_start, period_end = _compute_period_bounds()
    except ValueError:
        return jsonify({"success": False, "message": "Invalid date format"}), 400

    employee_id = request.args.get("employee_id")

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
        name = aes_decrypt(row["full_name"]) if row.get("full_name") else ""
        result.append(
            {
                "employee_id": row["employee_id"],
                "full_name": name,
                "role": row["role"],
                "hourly_rate": float(row["hourly_rate"] or 0),
                "days_worked": int(row["days_worked"] or 0),
                "total_hours": float(row["total_hours"] or 0),
                "total_pay": float(row["total_pay"] or 0),
            }
        )

    grand_total = round(sum(r["total_pay"] for r in result), 2)
    return jsonify(
        {
            "success": True,
            "period_start": str(period_start),
            "period_end": str(period_end),
            "records": result,
            "grand_total": grand_total,
        }
    )


@app.route("/api/payroll/period_detail", methods=["GET"])
def api_payroll_period_detail():
    """
    Day-by-day breakdown for a single employee within a pay period.
    Used when clicking an employee row to expand details.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    employee_id = request.args.get("employee_id")
    period_start = request.args.get("period_start")
    period_end = request.args.get("period_end")

    if not all([employee_id, period_start, period_end]):
        return jsonify({"success": False, "message": "Missing parameters"}), 400

    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        """
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
    """,
        (employee_id, period_start, period_end),
    )
    rows = cur.fetchall()
    cur.close()

    for row in rows:
        row["attendance_date"] = str(row["attendance_date"])
        row["hours_worked"] = float(row["hours_worked"] or 0)
        row["daily_pay"] = float(row["daily_pay"] or 0)
        row["hourly_rate"] = float(row["hourly_rate"] or 0)

    return jsonify({"success": True, "days": rows})


@app.route("/api/payroll/salary_detail", methods=["GET"])
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
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    employee_id = request.args.get("employee_id")
    period_start = request.args.get("period_start")
    period_end = request.args.get("period_end")

    if not all([employee_id, period_start, period_end]):
        return jsonify({"success": False, "message": "Missing parameters"}), 400

    try:
        from datetime import date as _date, timedelta as _td

        ps = datetime.strptime(period_start, "%Y-%m-%d").date()
        pe = datetime.strptime(period_end, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"success": False, "message": "Invalid date format"}), 400

    cur = mysql.connection.cursor(DictCursor)

    # ── Fetch employee info ──────────────────────────────────────────────────
    cur.execute(
        "SELECT employee_id, full_name, role, hourly_rate "
        "FROM employees WHERE employee_id = %s LIMIT 1",
        (employee_id,),
    )
    emp = cur.fetchone()
    if not emp:
        cur.close()
        return jsonify({"success": False, "message": "Employee not found"}), 404

    emp_name = aes_decrypt(emp["full_name"]) if emp.get("full_name") else ""
    base_rate = float(emp["hourly_rate"] or 0)

    # ── Fetch attendance rows in range ───────────────────────────────────────
    cur.execute(
        """
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
    """,
        (base_rate, base_rate, employee_id, ps, pe),
    )

    attendance_rows = cur.fetchall()
    cur.close()

    # Index existing rows by date for fast lookup
    att_by_date = {}
    for row in attendance_rows:
        key = str(row["attendance_date"])
        att_by_date[key] = {
            "attendance_date": key,
            "shift_type": row["shift_type"],
            "clock_in": row["clock_in"],
            "clock_out": row["clock_out"],
            "hours_worked": float(row["hours_worked"] or 0),
            "hourly_rate": float(row["hourly_rate"] or 0),
            "daily_pay": float(row["daily_pay"] or 0),
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
            days.append(
                {
                    "attendance_date": key,
                    "shift_type": None,
                    "clock_in": None,
                    "clock_out": None,
                    "hours_worked": 0.0,
                    "hourly_rate": base_rate,
                    "daily_pay": 0.0,
                }
            )
        current += _td(days=1)

    total_income = round(sum(d["daily_pay"] for d in days), 2)
    total_hours = round(sum(d["hours_worked"] for d in days), 2)
    days_worked = sum(1 for d in days if d["daily_pay"] > 0)

    return jsonify(
        {
            "success": True,
            "employee_id": int(employee_id),
            "full_name": emp_name,
            "role": emp["role"],
            "hourly_rate": base_rate,
            "period_start": str(ps),
            "period_end": str(pe),
            "total_income": total_income,
            "total_hours": total_hours,
            "days_worked": days_worked,
            "days": days,
        }
    )


@app.route("/api/payroll/generate", methods=["POST"])
def api_payroll_generate():
    """
    Compute and upsert payroll_periods rows for a given pay period.
    Uses INSERT ... ON DUPLICATE KEY UPDATE so re-running is idempotent.
    Real DB schema: payroll_periods(payroll_id, employee_id, period_start,
    period_end, total_hours, total_pay, days_worked, status, generated_at).
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    ps = data.get("period_start")
    pe = data.get("period_end")

    try:
        period_start = datetime.strptime(ps, "%Y-%m-%d").date()
        period_end = datetime.strptime(pe, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid period dates"}), 400

    cur = mysql.connection.cursor(DictCursor)

    cur.execute(
        """
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
    """,
        (period_start, period_end),
    )
    rows = cur.fetchall()

    generated = []
    for row in rows:
        name = aes_decrypt(row["full_name"]) if row.get("full_name") else ""
        hours = float(row["total_hours"] or 0)
        pay = float(row["total_pay"] or 0)
        days = int(row["days_worked"] or 0)

        cur.execute(
            """
            INSERT INTO payroll_periods
                (employee_id, period_start, period_end,
                 total_hours, total_pay, days_worked, status, generated_at)
            VALUES (%s, %s, %s, %s, %s, %s, 'draft', NOW())
            ON DUPLICATE KEY UPDATE
                total_hours  = VALUES(total_hours),
                total_pay    = VALUES(total_pay),
                days_worked  = VALUES(days_worked),
                generated_at = NOW()
        """,
            (row["employee_id"], period_start, period_end, hours, pay, days),
        )

        generated.append(
            {
                "employee_id": row["employee_id"],
                "full_name": name,
                "total_hours": round(hours, 2),
                "total_pay": pay,
                "days_worked": days,
            }
        )

    mysql.connection.commit()
    cur.close()

    grand_total = round(sum(r["total_pay"] for r in generated), 2)
    return jsonify(
        {
            "success": True,
            "period_start": str(period_start),
            "period_end": str(period_end),
            "records": generated,
            "grand_total": grand_total,
            "message": f"Payroll generated for {len(generated)} employee(s)",
        }
    )


@app.route("/api/payroll/history", methods=["GET"])
def api_payroll_history():
    """Return previously generated payroll records from payroll_periods table."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    cur = mysql.connection.cursor(DictCursor)
    cur.execute(
        """
        SELECT
            pp.payroll_id, pp.employee_id,
            pp.period_start, pp.period_end,
            pp.total_hours, pp.total_pay, pp.days_worked,
            pp.status, pp.generated_at, pp.finalized_at, pp.notes,
            e.full_name, e.role, e.hourly_rate
        FROM payroll_periods pp
        JOIN employees e ON e.employee_id = pp.employee_id
        ORDER BY pp.period_start DESC, e.full_name
        LIMIT 200
    """
    )
    rows = cur.fetchall()
    cur.close()

    for row in rows:
        row["full_name"] = aes_decrypt(row["full_name"]) if row.get("full_name") else ""
        row["period_start"] = str(row["period_start"])
        row["period_end"] = str(row["period_end"])
        row["generated_at"] = str(row["generated_at"])
        row["finalized_at"] = (
            str(row["finalized_at"]) if row.get("finalized_at") else None
        )
        row["total_hours"] = float(row["total_hours"] or 0)
        row["total_pay"] = float(row["total_pay"] or 0)
        row["hourly_rate"] = float(row["hourly_rate"] or 0)

    return jsonify({"success": True, "history": rows})


@app.route("/api/payroll/periods", methods=["GET"])
def api_payroll_periods():
    """
    Return a list of the last 12 pay periods (current + past) for the
    period-select dropdown in the payroll UI.

    Each entry:  { start, end, label, is_current }
    Periods follow the company's fixed 15-day cycle:
        - 1st - 15th
        - 16th - last day of month
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    from datetime import date as _date
    import calendar as _cal

    def _bounds(year, month, first_half):
        if first_half:
            return _date(year, month, 1), _date(year, month, 15)
        last = _cal.monthrange(year, month)[1]
        return _date(year, month, 16), _date(year, month, last)

    today = _date.today()
    is_first_half = today.day <= 15

    periods = []
    y, m, fh = today.year, today.month, is_first_half
    for i in range(12):
        ps, pe = _bounds(y, m, fh)
        if ps.month == pe.month:
            label = f"{ps.strftime('%b %d')} – {pe.strftime('%d, %Y')}"
        else:
            label = f"{ps.strftime('%b %d')} – {pe.strftime('%b %d, %Y')}"
        if i == 0:
            label += " (current)"
        periods.append(
            {
                "start": str(ps),
                "end": str(pe),
                "label": label,
                "is_current": i == 0,
            }
        )
        # Step back one half-month
        if fh:
            prev_m = m - 1 if m > 1 else 12
            prev_y = y if m > 1 else y - 1
            y, m, fh = prev_y, prev_m, False
        else:
            fh = True

    return jsonify({"success": True, "periods": periods})


@app.route("/api/payroll/period_summary", methods=["GET"])
def api_payroll_period_summary():
    """
    Payroll summary for a date range, keyed to what the frontend expects.

    Query params: start, end  (YYYY-MM-DD)

    Response:
        { success, period_start, period_end,
          records: [{employee_id, full_name, role, hourly_rate,
                     days_worked, total_hours, gross_pay}],
          total_payroll }
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    start_str = request.args.get("start") or request.args.get("period_start")
    end_str = request.args.get("end") or request.args.get("period_end")

    if not start_str or not end_str:
        return jsonify({"success": False, "message": "start and end are required"}), 400

    try:
        period_start = datetime.strptime(start_str, "%Y-%m-%d").date()
        period_end = datetime.strptime(end_str, "%Y-%m-%d").date()
        if period_end < period_start:
            raise ValueError("end before start")
    except ValueError as exc:
        return jsonify({"success": False, "message": f"Invalid date: {exc}"}), 400

    cur = mysql.connection.cursor(DictCursor)
    try:
        cur.execute(
            """
            SELECT
                e.employee_id,
                e.full_name,
                e.role,
                e.hourly_rate,
                COUNT(CASE WHEN a.clock_out IS NOT NULL THEN 1 END)   AS days_worked,
                ROUND(
                    SUM(CASE
                        WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                        THEN TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) / 60.0
                        ELSE 0
                    END), 2)                                          AS total_hours,
                ROUND(SUM(COALESCE(
                    NULLIF(a.daily_earnings, 0),
                    CASE
                        WHEN a.clock_in IS NOT NULL AND a.clock_out IS NOT NULL
                        THEN (TIMESTAMPDIFF(MINUTE, a.clock_in, a.clock_out) / 60.0)
                             * COALESCE(NULLIF(a.hourly_rate_snapshot, 0),
                                        e.hourly_rate, 0)
                        ELSE 0
                    END
                )), 2)                                                AS gross_pay
            FROM employees e
            LEFT JOIN attendance a
                ON  a.employee_id    = e.employee_id
                AND a.attendance_date BETWEEN %s AND %s
            WHERE e.employment_status = 'active'
            GROUP BY e.employee_id
            ORDER BY e.full_name
            """,
            (period_start, period_end),
        )
        rows = cur.fetchall()
    finally:
        cur.close()

    records = []
    for row in rows:
        name = aes_decrypt(row["full_name"]) if row.get("full_name") else ""
        records.append(
            {
                "employee_id": row["employee_id"],
                "full_name": name,
                "role": row["role"],
                "hourly_rate": float(row["hourly_rate"] or 0),
                "days_worked": int(row["days_worked"] or 0),
                "total_hours": float(row["total_hours"] or 0),
                "gross_pay": float(row["gross_pay"] or 0),
            }
        )

    total_payroll = round(sum(r["gross_pay"] for r in records), 2)

    return jsonify(
        {
            "success": True,
            "period_start": str(period_start),
            "period_end": str(period_end),
            "records": records,
            "total_payroll": total_payroll,
        }
    )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         INVENTORY SYSTEM                                     ║
# ║                                                                              ║
# ║  Tables:                                                                     ║
# ║    categories  — product categories (id, name, created_at)                   ║
# ║    products    — inventory items with stock, price, reorder threshold         ║
# ║                                                                              ║
# ║  Routes:                                                                     ║
# ║    GET  /inventory                   — render inventory page                  ║
# ║    GET  /api/inventory/stats         — summary card data                      ║
# ║    GET  /api/inventory/categories    — list all categories                    ║
# ║    POST /api/inventory/categories    — add category                           ║
# ║    GET  /api/inventory/items         — list products (search/filter/sort)     ║
# ║    POST /api/inventory/items         — create product                         ║
# ║    PUT  /api/inventory/items/<id>    — update product                         ║
# ║    DELETE /api/inventory/items/<id>  — delete product                         ║
# ║    POST /api/inventory/restock       — adjust stock quantity                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def _ensure_inventory_tables():
    """
    Idempotent DDL bootstrap for the inventory system.
    Creates `categories` and `products` tables if they don't exist,
    and seeds default categories on first run.
    """
    try:
        conn = mysql.connection
        cur = conn.cursor(DictCursor)

        # ── categories ────────────────────────────────────────────────────────
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS `categories` (
                `category_id`  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                `name`         VARCHAR(80)  NOT NULL,
                `created_at`   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY `uq_category_name` (`name`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """
        )

        # ── products ──────────────────────────────────────────────────────────
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS `products` (
                `product_id`       INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
                `category_id`      INT UNSIGNED  DEFAULT NULL,
                `name`             VARCHAR(120)  NOT NULL,
                `description`      TEXT          DEFAULT NULL,
                `sku`              VARCHAR(60)   DEFAULT NULL,
                `price`            DECIMAL(10,2) NOT NULL DEFAULT 0.00,
                `cost`             DECIMAL(10,2) NOT NULL DEFAULT 0.00,
                `stock`            INT           NOT NULL DEFAULT 0,
                `reorder_point`    INT           NOT NULL DEFAULT 5,
                `unit`             VARCHAR(30)   NOT NULL DEFAULT 'pcs',
                `is_active`        TINYINT(1)    NOT NULL DEFAULT 1,
                `created_at`       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `updated_at`       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX `idx_category` (`category_id`),
                INDEX `idx_active`   (`is_active`),
                CONSTRAINT `fk_product_category`
                    FOREIGN KEY (`category_id`) REFERENCES `categories`(`category_id`)
                    ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """
        )
        conn.commit()

        # ── add icon column if missing (idempotent) ─────────────────────────
        try:
            cur.execute(
                "ALTER TABLE `products` ADD COLUMN `icon` VARCHAR(10) NOT NULL DEFAULT '📦'"
            )
            conn.commit()
            app.logger.info("[inventory] Added icon column to products")
        except Exception:
            pass  # column already exists

        # ── add image_url column if missing (idempotent) ──────────────────────
        try:
            cur.execute(
                "ALTER TABLE `products` ADD COLUMN `image_url` VARCHAR(512) DEFAULT NULL"
            )
            conn.commit()
            app.logger.info("[inventory] Added image_url column to products")
        except Exception:
            pass  # column already exists

        # ── seed default categories if table is empty ─────────────────────────
        cur.execute("SELECT COUNT(*) AS cnt FROM `categories`")
        if cur.fetchone()["cnt"] == 0:
            defaults = [
                ("Books",),
                ("Flowers",),
                ("Café",),
                ("Stationery",),
                ("Gifts",),
            ]
            cur.executemany(
                "INSERT IGNORE INTO `categories` (name) VALUES (%s)", defaults
            )
            conn.commit()
            app.logger.info("[inventory] Seeded default categories")

        # ── seed sample products if table is empty ────────────────────────────
        cur.execute("SELECT COUNT(*) AS cnt FROM `products`")
        if cur.fetchone()["cnt"] == 0:
            cur.execute("SELECT category_id, name FROM categories")
            cat_map = {r["name"]: r["category_id"] for r in cur.fetchall()}
            samples = [
                (
                    cat_map.get("Books"),
                    "The Great Gatsby",
                    "A classic novel by F. Scott Fitzgerald",
                    "BK-001",
                    450.00,
                    200.00,
                    12,
                    5,
                    "pcs",
                ),
                (
                    cat_map.get("Books"),
                    "Pride & Prejudice",
                    "Jane Austen timeless romance",
                    "BK-002",
                    520.00,
                    220.00,
                    10,
                    5,
                    "pcs",
                ),
                (
                    cat_map.get("Books"),
                    "1984 by Orwell",
                    "Dystopian social science fiction",
                    "BK-003",
                    480.00,
                    210.00,
                    14,
                    5,
                    "pcs",
                ),
                (
                    cat_map.get("Flowers"),
                    "Rose Bouquet",
                    "Fresh red roses, dozen",
                    "FL-001",
                    850.00,
                    350.00,
                    8,
                    3,
                    "bunch",
                ),
                (
                    cat_map.get("Flowers"),
                    "Tulip Bunch",
                    "Seasonal tulips, mixed colors",
                    "FL-002",
                    680.00,
                    280.00,
                    4,
                    3,
                    "bunch",
                ),
                (
                    cat_map.get("Flowers"),
                    "Sunflower Bouquet",
                    "Bright sunflowers, half dozen",
                    "FL-003",
                    720.00,
                    300.00,
                    3,
                    3,
                    "bunch",
                ),
                (
                    cat_map.get("Café"),
                    "Cappuccino",
                    "Espresso with steamed milk foam",
                    "CF-001",
                    150.00,
                    40.00,
                    50,
                    10,
                    "cup",
                ),
                (
                    cat_map.get("Café"),
                    "Latte",
                    "Espresso with steamed milk",
                    "CF-002",
                    140.00,
                    38.00,
                    50,
                    10,
                    "cup",
                ),
                (
                    cat_map.get("Café"),
                    "Croissant",
                    "Buttery French pastry",
                    "CF-003",
                    120.00,
                    45.00,
                    30,
                    10,
                    "pcs",
                ),
                (
                    cat_map.get("Café"),
                    "Espresso",
                    "Double shot espresso",
                    "CF-004",
                    100.00,
                    30.00,
                    0,
                    10,
                    "cup",
                ),
                (
                    cat_map.get("Stationery"),
                    "Notebook Set",
                    "A5 ruled notebooks, pack of 3",
                    "ST-001",
                    280.00,
                    100.00,
                    25,
                    5,
                    "set",
                ),
                (
                    cat_map.get("Stationery"),
                    "Bookmark Set",
                    "Decorative bookmarks, pack of 5",
                    "ST-002",
                    150.00,
                    50.00,
                    30,
                    8,
                    "set",
                ),
                (
                    cat_map.get("Stationery"),
                    "Fountain Pen",
                    "Premium writing instrument",
                    "ST-003",
                    1200.00,
                    500.00,
                    7,
                    3,
                    "pcs",
                ),
                (
                    cat_map.get("Gifts"),
                    "Gift Basket",
                    "Assorted café and book combo",
                    "GF-001",
                    1500.00,
                    600.00,
                    5,
                    2,
                    "pcs",
                ),
                (
                    cat_map.get("Gifts"),
                    "Book Light",
                    "LED clip-on reading light",
                    "GF-002",
                    450.00,
                    180.00,
                    15,
                    5,
                    "pcs",
                ),
            ]
            cur.executemany(
                """
                INSERT INTO `products`
                    (category_id, name, description, sku, price, cost, stock,
                     reorder_point, unit)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
                samples,
            )
            conn.commit()
            app.logger.info("[inventory] Seeded sample products")

        cur.close()
        app.logger.info("[inventory] Inventory tables ensured")
    except Exception as exc:
        app.logger.error(f"[inventory] _ensure_inventory_tables failed: {exc}")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         SALES / TRANSACTIONS SYSTEM                          ║
# ║                                                                              ║
# ║  Tables:                                                                     ║
# ║    transactions      — one row per completed sale                            ║
# ║    transaction_items — line items for each transaction                       ║
# ║                                                                              ║
# ║  Routes:                                                                     ║
# ║    POST /api/pos/checkout            — complete a sale, deduct stock         ║
# ║    GET  /api/pos/transactions        — cashier's own recent transactions     ║
# ║    GET  /api/pos/transactions/<id>   — single transaction receipt detail     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def _ensure_sales_tables():
    """
    Idempotent DDL bootstrap for the sales/transactions system.
    Creates `transactions` and `transaction_items` tables if absent.
    """
    try:
        conn = mysql.connection
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS `transactions` (
                `transaction_id`   INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
                `cashier_id`       INT           NOT NULL,
                `cashier_name`     VARCHAR(255)  NOT NULL DEFAULT '',
                `subtotal`         DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                `discount_amount`  DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                `tax_amount`       DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                `total_amount`     DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                `amount_tendered`  DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                `change_amount`    DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                `payment_method`   ENUM('cash','card','gcash','maya','other')
                                   NOT NULL DEFAULT 'cash',
                `note`             VARCHAR(255)  DEFAULT NULL,
                `status`           ENUM('completed','voided') NOT NULL DEFAULT 'completed',
                `created_at`       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX `idx_cashier`    (`cashier_id`),
                INDEX `idx_created_at` (`created_at`),
                INDEX `idx_status`     (`status`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS `transaction_items` (
                `item_id`        INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
                `transaction_id` INT UNSIGNED  NOT NULL,
                `product_id`     INT UNSIGNED  DEFAULT NULL,
                `product_name`   VARCHAR(120)  NOT NULL,
                `category_name`  VARCHAR(80)   NOT NULL DEFAULT '',
                `unit_price`     DECIMAL(10,2) NOT NULL DEFAULT 0.00,
                `quantity`       INT           NOT NULL DEFAULT 1,
                `line_total`     DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                INDEX `idx_tx` (`transaction_id`),
                CONSTRAINT `fk_ti_transaction`
                    FOREIGN KEY (`transaction_id`)
                    REFERENCES `transactions`(`transaction_id`)
                    ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """
        )

        conn.commit()
        cur.close()
        app.logger.info("[sales] transactions + transaction_items tables ensured")
    except Exception as exc:
        app.logger.error(f"[sales] _ensure_sales_tables failed: {exc}")


# ── POST /api/pos/checkout ────────────────────────────────────────────────────


@app.route("/api/pos/checkout", methods=["POST"])
def api_pos_checkout():
    """
    Complete a POS sale.

    Body (JSON):
    {
      "items": [
        { "product_id": 1, "quantity": 2 },
        ...
      ],
      "payment_method": "cash",          // cash | card | gcash | maya | other
      "amount_tendered": 500.00,         // cash given by customer
      "discount_amount": 0.00,           // optional flat discount
      "note": "..."                      // optional note
    }

    Returns:
    {
      "success": true,
      "transaction_id": 42,
      "receipt": { ... }
    }
    """
    if "employee_id" not in session and not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    items_raw = data.get("items") or []
    if not items_raw:
        return jsonify({"success": False, "message": "Cart is empty"}), 400

    payment_method = (data.get("payment_method") or "cash").strip().lower()
    allowed_methods = {"cash", "card", "gcash", "maya", "other"}
    if payment_method not in allowed_methods:
        payment_method = "cash"

    try:
        discount_amount = round(float(data.get("discount_amount") or 0), 2)
        amount_tendered = round(float(data.get("amount_tendered") or 0), 2)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid numeric values"}), 400

    note = (data.get("note") or "").strip()[:255] or None

    # ── Resolve cashier info ────────────────────────────────────────────────────
    cashier_id = session.get("employee_id") or session.get("admin_id")
    cashier_name = session.get("full_name") or "Unknown"

    try:
        conn = mysql.connection
        cur = conn.cursor(DictCursor)

        # ── Validate items and fetch current prices from DB ─────────────────────
        product_ids = [int(i["product_id"]) for i in items_raw if i.get("product_id")]
        if not product_ids:
            cur.close()
            return jsonify({"success": False, "message": "No valid product IDs"}), 400

        fmt = ",".join(["%s"] * len(product_ids))
        cur.execute(
            f"""
            SELECT p.product_id, p.name, p.price, p.stock, p.unit,
                   p.cup_eligible,
                   COALESCE(c.name, 'Other') AS category_name
            FROM products p
            LEFT JOIN categories c ON c.category_id = p.category_id
            WHERE p.product_id IN ({fmt}) AND p.is_active = 1
        """,
            product_ids,
        )
        db_products = {r["product_id"]: r for r in cur.fetchall()}

        # Pre-fetch inv_items cup stock so we can validate BEFORE committing.
        # Maps e.g. "8oz" -> {"id": 1, "name": "8oz Cup", "stock": 45.0}
        cup_stock_map = {}
        cur.execute(
            "SELECT id, name, unit, stock FROM inv_items "
            "WHERE unit IN ('8oz','12oz','16oz') AND is_active=1"
        )
        for _cr in cur.fetchall():
            cup_stock_map[_cr["unit"]] = {
                "id": _cr["id"],
                "name": _cr["name"],
                "stock": float(_cr["stock"]),
            }

        # Build validated line items
        line_items = []
        subtotal = 0.00
        stock_errors = []
        # Track cumulative cup demand in this transaction to catch over-sells.
        cup_demand = {}  # { "8oz": 3, "12oz": 1, ... }

        for raw in items_raw:
            pid = int(raw.get("product_id", 0))
            qty = int(raw.get("quantity", 1))
            if pid not in db_products or qty <= 0:
                continue
            prod = db_products[pid]

            # cup_size is sent per-item from the cashier POS size picker
            cup_size = (str(raw.get("cup_size") or "")).strip() or None
            if cup_size and cup_size not in {"8oz", "12oz", "16oz"}:
                cup_size = None  # reject garbage values

            # ── Stock validation ────────────────────────────────────────────
            if bool(prod.get("cup_eligible")) and cup_size:
                # Cup-eligible drink: validate against inv_items cup stock
                cup_info = cup_stock_map.get(cup_size)
                if not cup_info:
                    stock_errors.append(
                        f"No '{cup_size} Cup' found in inventory — please add it first"
                    )
                    continue
                demand_so_far = cup_demand.get(cup_size, 0)
                available = cup_info["stock"] - demand_so_far
                if available < qty:
                    stock_errors.append(
                        f"'{prod['name']} ({cup_size})' — only {int(available)} "
                        f"{cup_size} Cup(s) left in inventory"
                    )
                    continue
                cup_demand[cup_size] = demand_so_far + qty
            elif not bool(prod.get("cup_eligible")) and prod["stock"] < qty:
                # Regular (non-cup) product: check products.stock
                stock_errors.append(
                    f"'{prod['name']}' only has {prod['stock']} pcs left"
                )
                continue

            line_total = round(float(prod["price"]) * qty, 2)
            line_items.append(
                {
                    "product_id": pid,
                    "product_name": prod["name"],
                    "category_name": prod["category_name"],
                    "unit_price": float(prod["price"]),
                    "quantity": qty,
                    "line_total": line_total,
                    "cup_size": cup_size,
                }
            )
            subtotal += line_total

        if stock_errors:
            cur.close()
            return jsonify({"success": False, "message": "; ".join(stock_errors)}), 409

        if not line_items:
            cur.close()
            return jsonify({"success": False, "message": "No valid items in cart"}), 400

        subtotal = round(subtotal, 2)

        # ── VAT-inclusive pricing (PH BIR standard) ─────────────────────────
        # Prices are VAT-inclusive. We extract the 12% VAT component.
        #   Net Sales  = subtotal / 1.12
        #   VAT Amount = Net Sales * 0.12
        #
        # For Senior/PWD discount (20%) the discount is applied on the
        # VAT-exclusive (net) price first, then VAT is added back:
        #   Discountable Net = Net Sales * 0.80
        #   VAT on discounted = Discountable Net * 0.12
        #   Total = Discountable Net + VAT on discounted
        # For manual flat discount it is deducted from the VAT-inclusive total.
        # ────────────────────────────────────────────────────────────────────
        discount_type_str = (data.get("discount_type") or "none").strip().lower()
        if discount_type_str not in {"none", "senior", "pwd", "manual"}:
            discount_type_str = "none"

        gross_net_sales = round(subtotal / 1.12, 2)  # VAT-exclusive subtotal
        gross_vat = round(gross_net_sales * 0.12, 2)

        if discount_type_str in ("senior", "pwd"):
            # 20% off the VAT-exclusive price, then re-add 12% VAT
            discount_rate = 0.20
            net_sales = round(gross_net_sales * (1 - discount_rate), 2)
            vat_amount = round(net_sales * 0.12, 2)
            total_amount = round(net_sales + vat_amount, 2)
            discount_amount = round(subtotal - total_amount, 2)
        elif discount_type_str == "manual":
            # Flat discount deducted from VAT-inclusive total
            discount_amount = min(
                round(float(data.get("discount_amount") or 0), 2), subtotal
            )
            total_amount = round(subtotal - discount_amount, 2)
            net_sales = round(total_amount / 1.12, 2)
            vat_amount = round(net_sales * 0.12, 2)
        else:
            # No discount
            discount_amount = 0.0
            net_sales = gross_net_sales
            vat_amount = gross_vat
            total_amount = subtotal

        # tax_amount kept for DB column compatibility (mirrors vat_amount)
        tax_amount = vat_amount
        change_amount = max(0.0, round(amount_tendered - total_amount, 2))

        if payment_method == "cash" and amount_tendered < total_amount:
            cur.close()
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Insufficient payment. Total is ₱{total_amount:.2f}",
                    }
                ),
                400,
            )

        # ── Write transaction header ────────────────────────────────────────────
        cur.execute(
            """
            INSERT INTO transactions
                (cashier_id, cashier_name, subtotal, discount_amount,
                 tax_amount, total_amount, amount_tendered, change_amount,
                 payment_method, note, discount_type, net_sales, vat_amount)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
            (
                cashier_id,
                cashier_name,
                subtotal,
                discount_amount,
                tax_amount,
                total_amount,
                amount_tendered,
                change_amount,
                payment_method,
                note,
                discount_type_str,
                net_sales,
                vat_amount,
            ),
        )
        transaction_id = cur.lastrowid

        # ── Write line items ────────────────────────────────────────────────────
        cur.executemany(
            """
            INSERT INTO transaction_items
                (transaction_id, product_id, product_name, category_name,
                 unit_price, quantity, line_total)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """,
            [
                (
                    transaction_id,
                    li["product_id"],
                    li["product_name"],
                    li["category_name"],
                    li["unit_price"],
                    li["quantity"],
                    li["line_total"],
                )
                for li in line_items
            ],
        )

        # ── Deduct product stock ────────────────────────────────────────────────
        for li in line_items:
            cur.execute(
                "UPDATE products SET stock = stock - %s WHERE product_id = %s",
                (li["quantity"], li["product_id"]),
            )

        # ── Auto-deduct cup packaging from inv_items (same transaction) ─────────
        # Runs synchronously inside the open transaction so the packaging deduction
        # is atomic with the sale: either both commit or both roll back.
        # cup_size ("8oz" / "12oz" / "16oz") was captured at the POS size-picker
        # and forwarded on every cup-eligible line item.
        cup_name_map = {"8oz": "8oz Cup", "12oz": "12oz Cup", "16oz": "16oz Cup"}
        for li in line_items:
            cup_unit = (li.get("cup_size") or "").strip()
            if not cup_unit or cup_unit not in CUP_UNITS:
                continue  # non-cup item — skip

            qty = int(li.get("quantity", 1))
            cup_display = cup_name_map.get(cup_unit)

            # Lookup inv_items row — prefer unit match, fall back to name match
            cur.execute(
                "SELECT id, name, stock FROM inv_items "
                "WHERE unit = %s AND type = 'packaging' AND is_active = 1 LIMIT 1",
                (cup_unit,),
            )
            cup_row = cur.fetchone()
            if not cup_row and cup_display:
                cur.execute(
                    "SELECT id, name, stock FROM inv_items "
                    "WHERE name = %s AND is_active = 1 LIMIT 1",
                    (cup_display,),
                )
                cup_row = cur.fetchone()

            if not cup_row:
                app.logger.warning(
                    f"[inv] No packaging item for '{cup_unit}' — skipping deduction "
                    f"(TXN #{transaction_id})"
                )
                continue

            # Decrement — floor at 0 to avoid negative stock
            cur.execute(
                "UPDATE inv_items "
                "SET stock = GREATEST(0, stock - %s) "
                "WHERE id = %s AND is_active = 1",
                (qty, cup_row["id"]),
            )

            # Fetch the resulting stock for the audit log
            cur.execute("SELECT stock FROM inv_items WHERE id = %s", (cup_row["id"],))
            updated_row = cur.fetchone()
            new_stock = (
                float(updated_row["stock"])
                if updated_row
                else max(0, float(cup_row["stock"]) - qty)
            )

            _log_inv_change(
                cur,
                item_id=cup_row["id"],
                item_name=cup_row["name"],
                unit=cup_unit,
                delta=-qty,
                stock_after=new_stock,
                source="sale",
                transaction_id=transaction_id,
                note=f"Auto-deducted via TXN #{transaction_id}",
                created_by=cashier_name,
            )
            app.logger.info(
                f"[inv] Deducted {qty}× {cup_unit} Cup for TXN #{transaction_id} "
                f"— stock now {new_stock}"
            )

        conn.commit()
        cur.close()

        receipt = {
            "transaction_id": transaction_id,
            "cashier_name": cashier_name,
            "items": line_items,
            "subtotal": subtotal,
            "discount_amount": discount_amount,
            "discount_type": discount_type_str,
            "net_sales": net_sales,
            "vat_amount": vat_amount,
            "tax_amount": tax_amount,
            "total_amount": total_amount,
            "amount_tendered": amount_tendered,
            "change_amount": change_amount,
            "payment_method": payment_method,
            "note": note,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        app.logger.info(
            f"[sales] Transaction #{transaction_id} — "
            f"₱{total_amount:.2f} by cashier #{cashier_id}"
        )
        return jsonify(
            {"success": True, "transaction_id": transaction_id, "receipt": receipt}
        )

    except Exception as exc:
        app.logger.error(f"[sales] checkout error: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/pos/transactions ─────────────────────────────────────────────────


@app.route("/api/pos/transactions", methods=["GET"])
def api_pos_transactions():
    """
    Return recent completed transactions for the logged-in cashier.
    Accepts optional ?limit=N (default 20, max 100) and ?date=YYYY-MM-DD.
    Admins see all cashiers; cashiers see only their own.
    """
    if "employee_id" not in session and not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        limit = min(int(request.args.get("limit", 50) or 50), 500)
    except (TypeError, ValueError):
        limit = 20

    date_str = request.args.get("date", "")
    cashier_id = session.get("employee_id")  # None for admins

    try:
        cur = mysql.connection.cursor(DictCursor)
        params = []
        where = ["t.status = 'completed'"]

        if cashier_id and not is_admin():
            where.append("t.cashier_id = %s")
            params.append(cashier_id)

        if date_str:
            try:
                from datetime import date as _date

                datetime.strptime(date_str, "%Y-%m-%d")
                where.append("DATE(t.created_at) = %s")
                params.append(date_str)
            except ValueError:
                pass

        sql = f"""
            SELECT t.transaction_id, t.cashier_id, t.cashier_name,
                   t.subtotal, t.discount_amount, t.tax_amount, t.total_amount,
                   t.amount_tendered, t.change_amount,
                   t.payment_method, t.note, t.created_at,
                   COUNT(ti.item_id) AS item_count,
                   e.role            AS cashier_role,
                   e.contact_number  AS cashier_contact_enc
            FROM transactions t
            LEFT JOIN transaction_items ti ON ti.transaction_id = t.transaction_id
            LEFT JOIN employees e ON e.employee_id = t.cashier_id
            WHERE {' AND '.join(where)}
            GROUP BY t.transaction_id
            ORDER BY t.created_at DESC
            LIMIT %s
        """
        params.append(limit)
        cur.execute(sql, params)
        rows = cur.fetchall()
        cur.close()

        txns = []
        for r in rows:
            # Decrypt AES-encrypted contact number if present
            raw_contact = r.get("cashier_contact_enc") or ""
            cashier_contact = aes_decrypt(raw_contact) if raw_contact else ""
            txns.append(
                {
                    "transaction_id": r["transaction_id"],
                    "cashier_id": r["cashier_id"],
                    "cashier_name": r["cashier_name"],
                    "cashier_role": r.get("cashier_role") or "cashier",
                    "cashier_contact": cashier_contact,
                    "subtotal": float(r["subtotal"]),
                    "discount_amount": float(r["discount_amount"]),
                    "tax_amount": float(r["tax_amount"]),
                    "total_amount": float(r["total_amount"]),
                    "amount_tendered": float(r["amount_tendered"]),
                    "change_amount": float(r["change_amount"]),
                    "payment_method": r["payment_method"],
                    "note": r["note"] or "",
                    "item_count": int(r["item_count"]),
                    "created_at": str(r["created_at"]),
                }
            )
        return jsonify({"success": True, "transactions": txns})
    except Exception as exc:
        app.logger.error(f"[sales] api_pos_transactions: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/pos/transactions/<id> ────────────────────────────────────────────


@app.route("/api/pos/transactions/<int:transaction_id>", methods=["GET"])
def api_pos_transaction_detail(transaction_id):
    """Return full receipt detail for a single transaction."""
    if "employee_id" not in session and not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            """
            SELECT t.transaction_id, t.cashier_id, t.cashier_name,
                   t.subtotal, t.discount_amount,
                   t.tax_amount, t.total_amount, t.amount_tendered, t.change_amount,
                   t.payment_method, t.note, t.status, t.created_at,
                   COALESCE(t.discount_type, 'none')                              AS discount_type,
                   COALESCE(t.net_sales,  ROUND(t.total_amount / 1.12, 2))        AS net_sales,
                   COALESCE(t.vat_amount, ROUND(t.total_amount / 1.12 * 0.12, 2)) AS vat_amount,
                   e.role           AS cashier_role,
                   e.contact_number AS cashier_contact_enc
            FROM transactions t
            LEFT JOIN employees e ON e.employee_id = t.cashier_id
            WHERE t.transaction_id = %s
        """,
            (transaction_id,),
        )
        txn = cur.fetchone()
        if not txn:
            cur.close()
            return jsonify({"success": False, "message": "Transaction not found"}), 404

        # Enforce ownership for cashiers
        if not is_admin():
            cashier_id = session.get("employee_id")
            if txn["cashier_id"] != cashier_id:
                cur.close()
                return jsonify({"success": False, "message": "Unauthorized"}), 403

        cur.execute(
            """
            SELECT product_name, category_name, unit_price, quantity, line_total
            FROM transaction_items WHERE transaction_id = %s ORDER BY item_id
        """,
            (transaction_id,),
        )
        items = cur.fetchall()
        cur.close()

        raw_contact = txn.get("cashier_contact_enc") or ""
        cashier_contact = aes_decrypt(raw_contact) if raw_contact else ""

        return jsonify(
            {
                "success": True,
                "transaction": {
                    "transaction_id": txn["transaction_id"],
                    "cashier_id": txn["cashier_id"],
                    "cashier_name": txn["cashier_name"],
                    "cashier_role": txn.get("cashier_role") or "cashier",
                    "cashier_contact": cashier_contact,
                    "subtotal": float(txn["subtotal"]),
                    "discount_amount": float(txn["discount_amount"]),
                    "tax_amount": float(txn["tax_amount"]),
                    "total_amount": float(txn["total_amount"]),
                    "amount_tendered": float(txn["amount_tendered"]),
                    "change_amount": float(txn["change_amount"]),
                    "payment_method": txn["payment_method"],
                    "note": txn["note"] or "",
                    "status": txn["status"],
                    "created_at": str(txn["created_at"]),
                    "discount_type": txn.get("discount_type") or "none",
                    "net_sales": float(txn.get("net_sales") or round(float(txn["total_amount"]) / 1.12, 2)),
                    "vat_amount": float(txn.get("vat_amount") or round(float(txn["total_amount"]) / 1.12 * 0.12, 2)),
                    "items": [
                        {
                            "product_name": i["product_name"],
                            "category_name": i["category_name"],
                            "unit_price": float(i["unit_price"]),
                            "quantity": i["quantity"],
                            "line_total": float(i["line_total"]),
                        }
                        for i in items
                    ],
                },
            }
        )
    except Exception as exc:
        app.logger.error(f"[sales] transaction_detail #{transaction_id}: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/sales/cashflow ───────────────────────────────────────────────────


@app.route("/api/sales/cashflow", methods=["GET"])
def api_sales_cashflow():
    """
    Return daily aggregated cash flow data for a date range.
    Query params: start (YYYY-MM-DD), end (YYYY-MM-DD)
    Returns: { success, daily_data: [{ date, transaction_count, items_sold, gross_sales,
               total_discount, net_revenue, cash_payment, digital_payment }, ...] }
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    start_date = request.args.get("start")
    end_date = request.args.get("end")

    if not start_date or not end_date:
        return (
            jsonify({"success": False, "message": "start and end dates required"}),
            400,
        )

    try:
        cur = mysql.connection.cursor(DictCursor)

        # Query to aggregate daily sales data
        cur.execute(
            """
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as transaction_count,
                SUM(COALESCE((
                    SELECT SUM(quantity) 
                    FROM transaction_items 
                    WHERE transaction_items.transaction_id = transactions.transaction_id
                ), 0)) as items_sold,
                SUM(subtotal) as gross_sales,
                SUM(discount_amount) as total_discount,
                SUM(total_amount) as net_revenue,
                SUM(CASE WHEN payment_method = 'cash' THEN total_amount ELSE 0 END) as cash_payment,
                SUM(CASE WHEN payment_method != 'cash' THEN total_amount ELSE 0 END) as digital_payment
            FROM transactions
            WHERE DATE(created_at) BETWEEN %s AND %s
              AND status = 'completed'
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        """,
            (start_date, end_date),
        )

        rows = cur.fetchall()
        cur.close()

        daily_data = []
        for row in rows:
            daily_data.append(
                {
                    "date": str(row["date"]),
                    "transaction_count": int(row["transaction_count"] or 0),
                    "items_sold": int(row["items_sold"] or 0),
                    "gross_sales": float(row["gross_sales"] or 0),
                    "total_discount": float(row["total_discount"] or 0),
                    "net_revenue": float(row["net_revenue"] or 0),
                    "cash_payment": float(row["cash_payment"] or 0),
                    "digital_payment": float(row["digital_payment"] or 0),
                }
            )

        return jsonify({"success": True, "daily_data": daily_data})

    except Exception as exc:
        app.logger.error(f"[sales] cashflow query failed: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── Shared low-stock helper ────────────────────────────────────────────────────


def _get_low_stock_items(limit=20):
    """
    Return a unified list of dicts for items at or below their reorder point,
    covering BOTH finished products (products table) AND ingredients/packaging
    (inv_items table).

    Each dict: {
        name, category_or_type, stock, unit, reorder_point,
        status ('out'|'low'), status_label, source ('product'|'ingredient'|'packaging')
    }
    Results are sorted: out-of-stock first, then by ascending stock, then name.
    The combined list is capped at `limit` rows.
    """
    cur = mysql.connection.cursor(DictCursor)

    # ── 1. Finished products ───────────────────────────────────────────────────
    cur.execute(
        """
        SELECT p.name,
               COALESCE(c.name, 'Uncategorised') AS category_or_type,
               p.stock,
               p.unit,
               p.reorder_point,
               'product' AS source
        FROM   products p
        LEFT JOIN categories c ON c.category_id = p.category_id
        WHERE  p.is_active = 1
          AND  p.stock <= p.reorder_point
        ORDER  BY p.stock ASC, p.name ASC
        LIMIT  %s
        """,
        (limit,),
    )
    product_rows = cur.fetchall()

    # ── 2. Ingredients & packaging (inv_items) ─────────────────────────────────
    cur.execute(
        """
        SELECT name,
               CONCAT(UPPER(SUBSTRING(type, 1, 1)), SUBSTRING(type, 2)) AS category_or_type,
               stock,
               unit,
               reorder_point,
               type AS source
        FROM   inv_items
        WHERE  is_active = 1
          AND  stock <= reorder_point
        ORDER  BY stock ASC, name ASC
        LIMIT  %s
        """,
        (limit,),
    )
    inv_rows = cur.fetchall()
    cur.close()

    # ── 3. Merge, annotate, sort, cap ─────────────────────────────────────────
    items = []
    for row in list(product_rows) + list(inv_rows):
        stock = float(row["stock"])
        reorder = float(row["reorder_point"])
        is_out = stock <= 0
        items.append(
            {
                "name":             row["name"],
                "category_or_type": row["category_or_type"],
                "stock":            stock,
                "unit":             row["unit"],
                "reorder_point":    reorder,
                "source":           row["source"],
                "status":           "out" if is_out else "low",
                "status_label":     "Out of Stock" if is_out else "Low Stock",
                # Legacy fields kept for backwards compatibility
                "category":         row["category_or_type"],
                "status_class":     "low" if is_out else "medium",
            }
        )

    # Sort: out-of-stock first, then by ascending stock level, then alphabetically
    items.sort(key=lambda i: (0 if i["status"] == "out" else 1, i["stock"], i["name"]))
    return items[:limit]


# ── Inventory page ─────────────────────────────────────────────────────────────


@app.route("/inventory")
def inventory():
    """Render the inventory management page (admin only)."""
    if not is_admin():
        return redirect(url_for("login"))
    # full_name is already decrypted when stored in session at login — do NOT decrypt again
    full_name = session.get("full_name") or "Admin"
    return render_template("inventory.html", full_name=full_name)


# ── Inventory API helpers ──────────────────────────────────────────────────────


def _stock_status(stock, reorder_point):
    """Return 'out', 'low', or 'ok' based on stock vs reorder threshold."""
    if stock == 0:
        return "out"
    if stock <= reorder_point:
        return "low"
    return "ok"


def _allowed_image(filename: str) -> bool:
    """Return True if the filename has an allowed image extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTS


# ── GET /api/inventory/stats ───────────────────────────────────────────────────


@app.route("/api/inventory/stats", methods=["GET"])
def api_inventory_stats():
    """Return summary statistics for the inventory dashboard cards."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            """
            SELECT
                COUNT(*)                                        AS total_products,
                SUM(stock)                                      AS total_units,
                SUM(CASE WHEN stock = 0 THEN 1 ELSE 0 END)     AS out_of_stock,
                SUM(CASE WHEN stock > 0 AND stock <= reorder_point THEN 1 ELSE 0 END) AS low_stock,
                SUM(stock * cost)                               AS inventory_cost,
                SUM(stock * price)                              AS inventory_value
            FROM products
            WHERE is_active = 1
        """
        )
        row = cur.fetchone()
        cur.close()
        return jsonify(
            {
                "success": True,
                "total_products": int(row["total_products"] or 0),
                "total_units": int(row["total_units"] or 0),
                "out_of_stock": int(row["out_of_stock"] or 0),
                "low_stock": int(row["low_stock"] or 0),
                "inventory_cost": float(row["inventory_cost"] or 0),
                "inventory_value": float(row["inventory_value"] or 0),
            }
        )
    except Exception as exc:
        app.logger.error(f"[inventory] api_inventory_stats: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/inventory/low-stock ──────────────────────────────────────────────


@app.route("/api/inventory/low-stock", methods=["GET"])
def api_inventory_low_stock():
    """
    Return items at or below their reorder point.
    Used by the dashboard for live low-stock polling and by the inventory
    page badge counter.  Accepts optional ?limit=N (default 50, max 200).
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        limit = min(int(request.args.get("limit", 50) or 50), 200)
    except (TypeError, ValueError):
        limit = 50
    try:
        items = _get_low_stock_items(limit=limit)
        return jsonify({"success": True, "items": items, "count": len(items)})
    except Exception as exc:
        app.logger.error(f"[inventory] low-stock API: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET/POST /api/inventory/categories ────────────────────────────────────────


@app.route("/api/inventory/categories", methods=["GET", "POST"])
def api_inventory_categories():
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    if request.method == "GET":
        try:
            cur = mysql.connection.cursor(DictCursor)
            cur.execute(
                """
                SELECT c.category_id, c.name,
                       COUNT(p.product_id) AS product_count
                FROM categories c
                LEFT JOIN products p
                    ON p.category_id = c.category_id AND p.is_active = 1
                GROUP BY c.category_id
                ORDER BY c.name
            """
            )
            cats = cur.fetchall()
            cur.close()
            for c in cats:
                c["product_count"] = int(c["product_count"])
            return jsonify({"success": True, "categories": cats})
        except Exception as exc:
            app.logger.error(f"[inventory] categories GET: {exc}")
            return jsonify({"success": False, "message": str(exc)}), 500

    # POST — add new category
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "message": "Category name is required"}), 400
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("INSERT INTO categories (name) VALUES (%s)", (name,))
        mysql.connection.commit()
        new_id = cur.lastrowid
        cur.close()
        return jsonify(
            {"success": True, "category_id": new_id, "message": "Category added"}
        )
    except Exception as exc:
        app.logger.error(f"[inventory] categories POST: {exc}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Category name already exists or DB error",
                }
            ),
            400,
        )


# ── GET /api/inventory/items ───────────────────────────────────────────────────


@app.route("/api/inventory/items", methods=["GET"])
def api_inventory_items():
    """
    List active products.
    Query params: search, category_id, stock_status (ok|low|out), sort (name|price_asc|price_desc|stock|stock_value)
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    search = (request.args.get("search") or "").strip()
    category_id = request.args.get("category_id")
    stock_status = request.args.get("stock_status", "")
    sort = request.args.get("sort", "name")

    order_map = {
        "name": "p.name ASC",
        "price_asc": "p.price ASC",
        "price_desc": "p.price DESC",
        "stock": "p.stock ASC",
        "stock_value": "(p.stock * p.price) DESC",
    }
    order_clause = order_map.get(sort, "p.name ASC")

    try:
        cur = mysql.connection.cursor(DictCursor)
        params = []
        where = ["p.is_active = 1"]

        if search:
            where.append("(p.name LIKE %s OR p.sku LIKE %s OR p.description LIKE %s)")
            like = f"%{search}%"
            params += [like, like, like]

        if category_id:
            where.append("p.category_id = %s")
            params.append(int(category_id))

        if stock_status == "out":
            where.append("p.stock = 0")
        elif stock_status == "low":
            where.append("p.stock > 0 AND p.stock <= p.reorder_point")
        elif stock_status == "ok":
            where.append("p.stock > p.reorder_point")

        sql = f"""
            SELECT p.product_id, p.name, p.description, p.sku, p.image_url,
                   p.icon, p.cup_eligible, p.price, p.cost, p.stock, p.reorder_point, p.unit,
                   p.created_at, p.updated_at,
                   c.category_id, c.name AS category_name
            FROM products p
            LEFT JOIN categories c ON c.category_id = p.category_id
            WHERE {' AND '.join(where)}
            ORDER BY {order_clause}
        """
        cur.execute(sql, params)
        rows = cur.fetchall()
        cur.close()

        items = []
        for r in rows:
            items.append(
                {
                    "product_id": r["product_id"],
                    "name": r["name"],
                    "description": r["description"] or "",
                    "sku": r["sku"] or "",
                    "image_url": r["image_url"] or "",
                    "icon": r["icon"] or "📦",
                    "price": float(r["price"]),
                    "cost": float(r["cost"]),
                    "stock": int(r["stock"]),
                    "reorder_point": int(r["reorder_point"]),
                    "unit": r["unit"],
                    "cup_eligible": bool(r.get("cup_eligible", 0)),
                    "status": _stock_status(r["stock"], r["reorder_point"]),
                    "category_id": r["category_id"],
                    "category_name": r["category_name"] or "Uncategorized",
                    "stock_value": round(float(r["price"]) * int(r["stock"]), 2),
                    "created_at": str(r["created_at"]),
                    "updated_at": str(r["updated_at"]),
                }
            )

        # Return both `items` and `products` so all frontend consumers work
        return jsonify(
            {"success": True, "items": items, "products": items, "total": len(items)}
        )
    except Exception as exc:
        app.logger.error(f"[inventory] api_inventory_items GET: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── POST /api/inventory/items ──────────────────────────────────────────────────


@app.route("/api/inventory/items", methods=["POST"])
def api_inventory_items_create():
    """Create a new product."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "message": "Product name is required"}), 400

    try:
        price = float(data.get("price", 0) or 0)
        cost = float(data.get("cost", 0) or 0)
        stock = int(data.get("stock", 0) or 0)
        reorder_point = int(data.get("reorder_point", 5) or 5)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid numeric values"}), 400

    category_id = data.get("category_id") or None
    sku = (data.get("sku") or "").strip() or None
    description = (data.get("description") or "").strip() or None
    unit = "pcs"  # size is now chosen at POS; unit is always pcs
    cup_eligible = 1 if data.get("cup_eligible") else 0
    image_url = (data.get("image_url") or "").strip() or None

    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            """
            INSERT INTO products
                (category_id, name, description, sku, price, cost,
                 stock, reorder_point, unit, cup_eligible, image_url)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
            (
                category_id,
                name,
                description,
                sku,
                price,
                cost,
                stock,
                reorder_point,
                unit,
                cup_eligible,
                image_url,
            ),
        )
        mysql.connection.commit()
        new_id = cur.lastrowid
        cur.close()
        # Broadcast the updated catalogue to all live SSE subscribers
        _threading.Thread(target=_sse_notify_product_change, daemon=True).start()
        return jsonify(
            {
                "success": True,
                "product_id": new_id,
                "message": f'"{name}" added to inventory',
            }
        )
    except Exception as exc:
        app.logger.error(f"[inventory] create product: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── PUT /api/inventory/items/<id> ─────────────────────────────────────────────


@app.route("/api/inventory/items/<int:product_id>", methods=["PUT"])
def api_inventory_items_update(product_id):
    """Update an existing product's details."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    try:
        price = float(data.get("price", 0) or 0)
        cost = float(data.get("cost", 0) or 0)
        stock = int(data.get("stock", 0) or 0)
        reorder_point = int(data.get("reorder_point", 5) or 5)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid numeric values"}), 400

    name = (data.get("name") or "").strip()
    category_id = data.get("category_id") or None
    sku = (data.get("sku") or "").strip() or None
    description = (data.get("description") or "").strip() or None
    unit = "pcs"  # size is now chosen at POS; unit is always pcs
    cup_eligible = 1 if data.get("cup_eligible") else 0
    image_url = (data.get("image_url") or "").strip() or None

    if not name:
        return jsonify({"success": False, "message": "Product name is required"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            UPDATE products
               SET category_id   = %s,
                   name          = %s,
                   description   = %s,
                   sku           = %s,
                   price         = %s,
                   cost          = %s,
                   stock         = %s,
                   reorder_point = %s,
                   unit          = %s,
                   cup_eligible  = %s,
                   image_url     = %s
             WHERE product_id = %s AND is_active = 1
        """,
            (
                category_id,
                name,
                description,
                sku,
                price,
                cost,
                stock,
                reorder_point,
                unit,
                cup_eligible,
                image_url,
                product_id,
            ),
        )
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return jsonify({"success": False, "message": "Product not found"}), 404
        # Broadcast the updated catalogue to all live SSE subscribers
        _threading.Thread(target=_sse_notify_product_change, daemon=True).start()
        return jsonify({"success": True, "message": f'"{name}" updated'})
    except Exception as exc:
        app.logger.error(f"[inventory] update product #{product_id}: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── DELETE /api/inventory/items/<id> ──────────────────────────────────────────


@app.route("/api/inventory/items/<int:product_id>", methods=["DELETE"])
def api_inventory_items_delete(product_id):
    """Soft-delete a product (sets is_active = 0)."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE products SET is_active = 0 WHERE product_id = %s", (product_id,)
        )
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return jsonify({"success": False, "message": "Product not found"}), 404
        # Broadcast the updated catalogue to all live SSE subscribers
        _threading.Thread(target=_sse_notify_product_change, daemon=True).start()
        return jsonify({"success": True, "message": "Product removed from inventory"})
    except Exception as exc:
        app.logger.error(f"[inventory] delete product #{product_id}: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── POST /api/inventory/restock ───────────────────────────────────────────────


@app.route("/api/inventory/restock", methods=["POST"])
def api_inventory_restock():
    """
    Adjust a product's stock level.
    Body: { product_id, adjustment, note }
    adjustment is a signed integer (+N to add, -N to remove).
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    try:
        adjustment = int(data.get("adjustment", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid adjustment value"}), 400

    if not product_id:
        return jsonify({"success": False, "message": "product_id required"}), 400

    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            "SELECT product_id, name, stock, reorder_point FROM products WHERE product_id=%s AND is_active=1",
            (product_id,),
        )
        product = cur.fetchone()
        if not product:
            cur.close()
            return jsonify({"success": False, "message": "Product not found"}), 404

        new_stock = max(0, int(product["stock"]) + adjustment)
        cur.execute(
            "UPDATE products SET stock = %s WHERE product_id = %s",
            (new_stock, product_id),
        )
        mysql.connection.commit()
        cur.close()
        return jsonify(
            {
                "success": True,
                "new_stock": new_stock,
                "status": _stock_status(new_stock, int(product["reorder_point"])),
                "message": f"Stock updated to {new_stock} units",
            }
        )
    except Exception as exc:
        app.logger.error(f"[inventory] restock product #{product_id}: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


_migration_done = False


@app.before_request
def ensure_migration():
    """Run the DB migration exactly once after the app has a live DB connection."""
    global _migration_done
    if not _migration_done:
        _migration_done = True  # Set first so a crash doesn't cause infinite loops
        run_auto_migration()
    # Run the trash purge on every request (rate-limited internally to every 5 min)
    _purge_expired_trash()


# ═══════════════════════════════════════════════════════════════
# Books & Blooms Café — New Inventory API Routes
# Add these routes to app.py (alongside the existing routes)
# ═══════════════════════════════════════════════════════════════
#
# These routes power the redesigned inventory.html:
#   GET    /api/inv_items            - list all inventory items
#   POST   /api/inv_items            - create item
#   PUT    /api/inv_items/<id>       - update item
#   DELETE /api/inv_items/<id>       - soft-delete item
#   POST   /api/inv_items/adjust     - manual stock adjustment
#   GET    /api/inv_items/log        - recent deduction log
#
# Auto-deduction on checkout:
#   Modify the existing /api/pos/checkout route to call
#   _deduct_cups_for_sale(transaction_id, items) after committing
#   the transaction.
# ═══════════════════════════════════════════════════════════════


# ── Helpers ───────────────────────────────────────────────────

CUP_UNITS = {"8oz", "12oz", "16oz"}  # units that auto-deduct from inv_items


def _log_inv_change(
    cur,
    item_id,
    item_name,
    unit,
    delta,
    stock_after,
    source="manual",
    transaction_id=None,
    note=None,
    created_by=None,
):
    """Insert a row into inv_log."""
    cur.execute(
        """
        INSERT INTO inv_log
            (item_id, item_name, unit, delta, stock_after,
             source, transaction_id, note, created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """,
        (
            item_id,
            item_name,
            unit,
            delta,
            stock_after,
            source,
            transaction_id,
            note,
            created_by,
        ),
    )


def _deduct_cups_for_sale(transaction_id, items, cashier_name=""):
    """
    Called after a successful checkout.
    For each cart item that carries a cup_size (8oz / 12oz / 16oz),
    deduct 1 cup per unit sold from inv_items.
    The cup_size is chosen at the POS at the time of sale — it is NOT
    stored on the product record any more.
    """
    try:
        cur = mysql.connection.cursor(DictCursor)
        for item in items:
            quantity = int(item.get("quantity", 1))
            # cup_size is passed directly from the POS cart item
            cup_unit = (item.get("cup_size") or "").strip()
            if not cup_unit or cup_unit not in CUP_UNITS or quantity <= 0:
                continue
            # Map cup_unit to the canonical display name used in inv_items
            cup_name_map = {"8oz": "8oz Cup", "12oz": "12oz Cup", "16oz": "16oz Cup"}
            cup_display_name = cup_name_map.get(cup_unit)

            # Try lookup by unit first, then fall back to name
            cur.execute(
                "SELECT id, name, stock FROM inv_items "
                "WHERE unit=%s AND type='packaging' AND is_active=1 LIMIT 1",
                (cup_unit,),
            )
            cup = cur.fetchone()
            if not cup and cup_display_name:
                # Fallback: match by name (covers edge cases where unit column differs)
                cur.execute(
                    "SELECT id, name, stock FROM inv_items "
                    "WHERE name=%s AND is_active=1 LIMIT 1",
                    (cup_display_name,),
                )
                cup = cur.fetchone()
            if not cup:
                app.logger.warning(
                    f"[inv] No packaging item for {cup_unit} — skipping deduction"
                )
                continue
            new_stock = max(0, float(cup["stock"]) - quantity)
            # Direct UPDATE by name as well (belt-and-suspenders, matches task spec)
            cur.execute(
                "UPDATE inv_items SET stock = stock - %s "
                "WHERE name = %s AND is_active = 1",
                (quantity, cup["name"]),
            )
            # Re-fetch actual new stock for logging
            cur.execute("SELECT stock FROM inv_items WHERE id=%s", (cup["id"],))
            updated = cur.fetchone()
            new_stock = float(updated["stock"]) if updated else new_stock
            _log_inv_change(
                cur,
                item_id=cup["id"],
                item_name=cup["name"],
                unit=cup_unit,
                delta=-quantity,
                stock_after=new_stock,
                source="sale",
                transaction_id=transaction_id,
                note=f"Auto-deducted from TXN #{transaction_id}",
                created_by=cashier_name,
            )
        mysql.connection.commit()
        cur.close()
    except Exception as exc:
        app.logger.error(f"[inv] _deduct_cups_for_sale TXN#{transaction_id}: {exc}")


# ── GET /api/inv_items ────────────────────────────────────────


@app.route("/api/inv_items", methods=["GET"])
def api_inv_items_list():
    """Return all active inventory items (ingredients + packaging)."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            """
            SELECT id, name, type, stock, unit, reorder_point, note, updated_at
            FROM inv_items
            WHERE is_active = 1
            ORDER BY type, name
        """
        )
        items = cur.fetchall()
        cur.close()
        # Attach status label
        for item in items:
            s = float(item["stock"])
            r = float(item["reorder_point"])
            item["status"] = "out" if s <= 0 else ("low" if s <= r else "ok")
            item["stock"] = float(item["stock"])
            item["reorder_point"] = float(item["reorder_point"])
        return jsonify({"success": True, "items": items})
    except Exception as exc:
        app.logger.error(f"[inv_items] list: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── POST /api/inv_items ───────────────────────────────────────


@app.route("/api/inv_items", methods=["POST"])
def api_inv_items_create():
    """Create a new inventory item."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "message": "Name is required"}), 400
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            """
            INSERT INTO inv_items (name, type, stock, unit, reorder_point, note)
            VALUES (%s,%s,%s,%s,%s,%s)
        """,
            (
                name,
                data.get("type", "ingredient"),
                float(data.get("stock", 0) or 0),
                (data.get("unit") or "pcs").strip(),
                float(data.get("reorder_point", 10) or 10),
                (data.get("note") or "").strip() or None,
            ),
        )
        mysql.connection.commit()
        new_id = cur.lastrowid
        cur.close()
        return jsonify(
            {"success": True, "id": new_id, "message": f'"{name}" added to inventory'}
        )
    except Exception as exc:
        app.logger.error(f"[inv_items] create: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── PUT /api/inv_items/<id> ───────────────────────────────────


@app.route("/api/inv_items/<int:item_id>", methods=["PUT"])
def api_inv_items_update(item_id):
    """Update an existing inventory item."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "message": "Name is required"}), 400
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            UPDATE inv_items
               SET name=%s, type=%s, stock=%s, unit=%s, reorder_point=%s, note=%s
             WHERE id=%s AND is_active=1
        """,
            (
                name,
                data.get("type", "ingredient"),
                float(data.get("stock", 0) or 0),
                (data.get("unit") or "pcs").strip(),
                float(data.get("reorder_point", 10) or 10),
                (data.get("note") or "").strip() or None,
                item_id,
            ),
        )
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return jsonify({"success": False, "message": "Item not found"}), 404
        return jsonify({"success": True, "message": f'"{name}" updated'})
    except Exception as exc:
        app.logger.error(f"[inv_items] update #{item_id}: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── DELETE /api/inv_items/<id> ────────────────────────────────


@app.route("/api/inv_items/<int:item_id>", methods=["DELETE"])
def api_inv_items_delete(item_id):
    """Soft-delete an inventory item."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE inv_items SET is_active=0 WHERE id=%s", (item_id,))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return jsonify({"success": False, "message": "Item not found"}), 404
        return jsonify({"success": True, "message": "Item removed"})
    except Exception as exc:
        app.logger.error(f"[inv_items] delete #{item_id}: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── POST /api/inv_items/adjust ────────────────────────────────


@app.route("/api/inv_items/adjust", methods=["POST"])
def api_inv_items_adjust():
    """
    Manually adjust stock level.
    Body: { id, delta (signed float), note }
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    item_id = data.get("id")
    try:
        delta = float(data.get("delta", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid delta"}), 400
    if not item_id:
        return jsonify({"success": False, "message": "id required"}), 400
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            "SELECT id, name, stock, unit FROM inv_items WHERE id=%s AND is_active=1",
            (item_id,),
        )
        item = cur.fetchone()
        if not item:
            cur.close()
            return jsonify({"success": False, "message": "Item not found"}), 404
        new_stock = max(0, float(item["stock"]) + delta)
        cur.execute("UPDATE inv_items SET stock=%s WHERE id=%s", (new_stock, item_id))
        _log_inv_change(
            cur,
            item_id=item["id"],
            item_name=item["name"],
            unit=item["unit"],
            delta=delta,
            stock_after=new_stock,
            source="manual",
            note=(data.get("note") or "").strip() or None,
            created_by=session.get("full_name") or session.get("username") or "Admin",
        )
        mysql.connection.commit()
        cur.close()
        return jsonify(
            {
                "success": True,
                "new_stock": new_stock,
                "message": f'Stock updated to {new_stock} {item["unit"]}',
            }
        )
    except Exception as exc:
        app.logger.error(f"[inv_items] adjust #{item_id}: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/inv_items/log ────────────────────────────────────


@app.route("/api/inv_items/log", methods=["GET"])
def api_inv_items_log():
    """Return recent inventory deduction log entries."""
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    limit = min(int(request.args.get("limit", 30)), 100)
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            """
            SELECT log_id, item_name, unit, delta, stock_after, source,
                   transaction_id, note, created_by,
                   DATE_FORMAT(created_at, '%%b %%d, %%Y %%h:%%i %%p') AS created_at
            FROM inv_log
            ORDER BY log_id DESC
            LIMIT %s
        """,
            (limit,),
        )
        log = cur.fetchall()
        cur.close()
        for row in log:
            row["delta"] = float(row["delta"])
            row["stock_after"] = float(row["stock_after"])
        return jsonify({"success": True, "log": log})
    except Exception as exc:
        app.logger.error(f"[inv_items] log: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════
# MODIFY EXISTING /api/pos/checkout
# ═══════════════════════════════════════════════════════════════
#
# In your existing checkout route, AFTER committing the
# transaction and BEFORE returning the response, add:
#
#   _deduct_cups_for_sale(
#       transaction_id = new_transaction_id,
#       items          = payload_items,   # list of dicts with product_id, quantity
#       cashier_name   = session.get('full_name', 'Cashier'),
#   )
#
# Example (inside your existing checkout function):
#
#   mysql.connection.commit()
#   new_id = cur.lastrowid
#   cur.close()
#
#   # ← ADD THIS CALL:
#   _deduct_cups_for_sale(new_id, data.get('items', []), session.get('full_name','Cashier'))
#
#   return jsonify({'success': True, 'transaction_id': new_id, 'receipt': receipt_data})
#
# ═══════════════════════════════════════════════════════════════


# ── Auto-migration (call inside run_auto_migration) ───────────


def _ensure_employee_applications_table():
    """
    Idempotent DDL bootstrap for employee_applications.
    Present in the live DB but never auto-created by app.py — safe to add.
    """
    try:
        conn = mysql.connection
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS `employee_applications` (
                `application_id` INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
                `full_name`      VARCHAR(255) NOT NULL DEFAULT \'\',
                `email`          VARCHAR(255) NOT NULL DEFAULT \'\',
                `username`       VARCHAR(255) NOT NULL DEFAULT \'\',
                `role`           ENUM(\'admin\',\'manager\',\'cashier\') NOT NULL DEFAULT \'cashier\',
                `contact_number` VARCHAR(255) NOT NULL DEFAULT \'\',
                `status`         ENUM(\'pending\',\'approved\',\'rejected\') NOT NULL DEFAULT \'pending\',
                `created_at`     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY `email`    (`email`),
                UNIQUE KEY `username` (`username`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """
        )
        conn.commit()
        cur.close()
        app.logger.info("[migration] employee_applications table ensured")
    except Exception as exc:
        app.logger.error(f"[migration] _ensure_employee_applications_table: {exc}")


def _ensure_inv_tables():
    """
    Create inv_items and inv_log tables if they don't exist.
    Call this inside run_auto_migration() at startup.
    """
    try:
        conn = mysql.connection
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS `inv_items` (
              `id`            int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
              `name`          varchar(120) NOT NULL,
              `type`          enum('ingredient','packaging') NOT NULL DEFAULT 'ingredient',
              `stock`         decimal(12,2) NOT NULL DEFAULT 0,
              `unit`          varchar(20) NOT NULL DEFAULT 'pcs',
              `reorder_point` decimal(12,2) NOT NULL DEFAULT 10,
              `note`          varchar(255) DEFAULT NULL,
              `is_active`     tinyint(1) NOT NULL DEFAULT 1,
              `created_at`    timestamp NOT NULL DEFAULT current_timestamp(),
              `updated_at`    timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
              PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS `inv_log` (
              `log_id`         int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
              `item_id`        int(10) UNSIGNED NOT NULL,
              `item_name`      varchar(120) NOT NULL DEFAULT '',
              `unit`           varchar(20) NOT NULL DEFAULT 'pcs',
              `delta`          decimal(12,2) NOT NULL,
              `stock_after`    decimal(12,2) NOT NULL,
              `source`         enum('sale','manual') NOT NULL DEFAULT 'manual',
              `transaction_id` int(10) UNSIGNED DEFAULT NULL,
              `note`           varchar(255) DEFAULT NULL,
              `created_by`     varchar(80) DEFAULT NULL,
              `created_at`     timestamp NOT NULL DEFAULT current_timestamp(),
              PRIMARY KEY (`log_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """
        )
        # Seed default cup items if none exist
        cur.execute(
            "SELECT COUNT(*) AS c FROM inv_items WHERE unit IN ('8oz','12oz','16oz')"
        )
        if cur.fetchone()[0] == 0:
            cur.executemany(
                "INSERT INTO inv_items (name, type, stock, unit, reorder_point, note) VALUES (%s,'packaging',0,%s,20,%s)",
                [
                    ("8oz Cup", "8oz", "Small cup — auto-deducted on sales"),
                    ("12oz Cup", "12oz", "Medium cup — auto-deducted on sales"),
                    ("16oz Cup", "16oz", "Large cup — auto-deducted on sales"),
                ],
            )
        conn.commit()
        cur.close()
        app.logger.info("[migration] inv_items + inv_log tables ready")
    except Exception as exc:
        app.logger.error(f"[migration] _ensure_inv_tables: {exc}")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                   MISSING / ALIAS ROUTES (Database Integration)             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


# ── GET /api/products/stream ─────────────────────────────────────────────────
# Server-Sent Events: pushes a full product snapshot whenever the catalogue
# changes.  Clients subscribe once; the server re-sends on a 5-second heartbeat
# so reconnects after network hiccups are seamless.
# Used by both cashier_dashboard.html and product_management.html.

import threading as _threading
import queue as _queue
import time as _time

_sse_subscribers: list = []  # list of queue.Queue objects
_sse_lock = _threading.Lock()


def _sse_broadcast(payload: str):
    """Push a payload to every waiting SSE subscriber queue."""
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(payload)
            except _queue.Full:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)


def _sse_notify_product_change():
    """
    Fetch the current active product list and broadcast it to all SSE clients.
    Called after every create / update / delete of a product.
    """
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            """
            SELECT p.product_id, p.name, p.description, p.sku,
                   p.image_url, p.icon, p.price, p.cost,
                   p.stock, p.reorder_point, p.unit,
                   p.is_active,
                   c.category_id, c.name AS category_name
            FROM products p
            LEFT JOIN categories c ON c.category_id = p.category_id
            WHERE p.is_active = 1
            ORDER BY c.name, p.name
            """
        )
        rows = cur.fetchall()
        cur.close()
        items = [
            {
                "product_id": r["product_id"],
                "name": r["name"],
                "description": r["description"] or "",
                "sku": r["sku"] or "",
                "image_url": r["image_url"] or "",
                "icon": r["icon"] or "📦",
                "price": float(r["price"]),
                "cost": float(r["cost"]),
                "stock": int(r["stock"]),
                "reorder_point": int(r["reorder_point"]),
                "unit": r["unit"],
                "category_id": r["category_id"],
                "category_name": r["category_name"] or "Other",
            }
            for r in rows
        ]
        payload = "data: " + json.dumps({"type": "products", "items": items}) + "\n\n"
        _sse_broadcast(payload)
    except Exception as exc:
        app.logger.error(f"[sse] _sse_notify_product_change: {exc}")


@app.route("/api/products/stream", methods=["GET"])
def api_products_stream():
    """
    SSE endpoint.  Streams product catalogue snapshots to subscribers.
    Each message is: data: <JSON>\n\n
    The JSON shape: { type: "products", items: [...] }
    A keepalive comment (: ping) is sent every 25 s to prevent proxy timeouts.
    """
    if "employee_id" not in session and not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    q: _queue.Queue = _queue.Queue(maxsize=10)
    with _sse_lock:
        _sse_subscribers.append(q)

    def generate():
        # Send an immediate snapshot so the client renders instantly on connect
        try:
            _sse_notify_product_change()
        except Exception:
            pass
        try:
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield msg
                except _queue.Empty:
                    # keepalive ping — prevents Nginx / browser from closing idle SSE
                    yield ": ping\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                try:
                    _sse_subscribers.remove(q)
                except ValueError:
                    pass

    from flask import Response, stream_with_context

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable Nginx buffering
        },
    )


# ── GET /api/pos/products ─────────────────────────────────────────────────────
# Alias used by cashier_dashboard.html (calls /api/pos/products).
# The canonical route is /api/products/pos — this alias proxies it so both
# URLs work without duplicating logic.


@app.route("/api/pos/products", methods=["GET"])
def api_pos_products():
    """
    POS product catalogue for the cashier dashboard.
    Returns active products grouped by category.
    Alias for /api/products/pos — cashier_dashboard.html uses this URL.
    """
    if "employee_id" not in session and not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        cur = mysql.connection.cursor(DictCursor)

        cur.execute(
            """
            SELECT c.category_id, c.name,
                   COUNT(p.product_id) AS product_count
            FROM   categories c
            LEFT   JOIN products p
                   ON p.category_id = c.category_id AND p.is_active = 1
            GROUP  BY c.category_id
            HAVING product_count > 0
            ORDER  BY c.name
        """
        )
        categories = [
            {
                "category_id": c["category_id"],
                "name": c["name"],
                "product_count": int(c["product_count"]),
            }
            for c in cur.fetchall()
        ]

        cur.execute(
            """
            SELECT p.product_id, p.name, p.description,
                   p.image_url, p.icon, p.cup_eligible, p.price, p.stock, p.unit,
                   c.category_id, c.name AS category_name
            FROM   products p
            LEFT   JOIN categories c ON c.category_id = p.category_id
            WHERE  p.is_active = 1
            ORDER  BY c.name, p.name
        """
        )
        items = [
            {
                "product_id": r["product_id"],
                "name": r["name"],
                "description": r["description"] or "",
                "image_url": r["image_url"] or "",
                "icon": r["icon"] or "📦",
                "cup_eligible": bool(r.get("cup_eligible", 0)),
                "price": float(r["price"]),
                "stock": int(r["stock"]),
                "unit": r["unit"],
                "category_id": r["category_id"],
                "category_name": r["category_name"] or "Other",
            }
            for r in cur.fetchall()
        ]
        cur.close()
        # Return both `items` and `products` so old and new frontend code both work
        return jsonify(
            {
                "success": True,
                "items": items,
                "products": items,
                "categories": categories,
            }
        )
    except Exception as exc:
        app.logger.error(f"[products] api_pos_products: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── POST /api/inventory/bulk-action ──────────────────────────────────────────
# Bulk operations on multiple products: delete, restock, set_reorder.


@app.route("/api/inventory/bulk-action", methods=["POST"])
def api_inventory_bulk_action():
    """
    Perform a bulk action on selected inventory items.

    Body (JSON):
    {
      "action":      "delete" | "restock" | "set_reorder",
      "product_ids": [1, 2, 3, ...],
      "value":       <int>   // required for restock (delta) and set_reorder (new threshold)
    }

    Responses:
      { "success": true, "affected": N, "message": "..." }
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "").strip()
    product_ids = data.get("product_ids") or []

    if not action or not product_ids:
        return (
            jsonify(
                {"success": False, "message": "action and product_ids are required"}
            ),
            400,
        )

    # Sanitise: ensure all IDs are positive integers
    try:
        product_ids = [int(pid) for pid in product_ids if int(pid) > 0]
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid product_ids"}), 400

    if not product_ids:
        return (
            jsonify({"success": False, "message": "No valid product IDs provided"}),
            400,
        )

    allowed_actions = {"delete", "restock", "set_reorder"}
    if action not in allowed_actions:
        return (
            jsonify({"success": False, "message": f"Unknown action '{action}'"}),
            400,
        )

    try:
        cur = mysql.connection.cursor()
        fmt = ",".join(["%s"] * len(product_ids))
        affected = 0

        if action == "delete":
            # Soft-delete: mark is_active = 0
            cur.execute(
                f"UPDATE products SET is_active = 0 WHERE product_id IN ({fmt}) AND is_active = 1",
                product_ids,
            )
            affected = cur.rowcount
            msg = f"{affected} product(s) removed from inventory"

        elif action == "restock":
            try:
                delta = int(data.get("value", 0))
            except (TypeError, ValueError):
                cur.close()
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "value (integer delta) required for restock",
                        }
                    ),
                    400,
                )

            # Ensure stock never goes below 0
            if delta >= 0:
                cur.execute(
                    f"UPDATE products SET stock = stock + %s WHERE product_id IN ({fmt}) AND is_active = 1",
                    [delta] + product_ids,
                )
            else:
                cur.execute(
                    f"UPDATE products SET stock = GREATEST(0, stock + %s) WHERE product_id IN ({fmt}) AND is_active = 1",
                    [delta] + product_ids,
                )
            affected = cur.rowcount
            sign = "+" if delta >= 0 else ""
            msg = f"Stock adjusted by {sign}{delta} for {affected} product(s)"

        elif action == "set_reorder":
            try:
                new_threshold = max(0, int(data.get("value", 5)))
            except (TypeError, ValueError):
                cur.close()
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "value (integer threshold) required for set_reorder",
                        }
                    ),
                    400,
                )

            cur.execute(
                f"UPDATE products SET reorder_point = %s WHERE product_id IN ({fmt}) AND is_active = 1",
                [new_threshold] + product_ids,
            )
            affected = cur.rowcount
            msg = f"Reorder point set to {new_threshold} for {affected} product(s)"

        mysql.connection.commit()
        cur.close()

        app.logger.info(
            f"[inventory] bulk-action={action} ids={product_ids} affected={affected}"
        )
        return jsonify({"success": True, "affected": affected, "message": msg})

    except Exception as exc:
        app.logger.error(f"[inventory] bulk-action error: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/inventory/history/<product_id> ───────────────────────────────────
# Returns the full movement history for a single product, combining:
#   • Sales deductions (from transaction_items)
#   • Manual restock adjustments (from inv_log where item matches by name/unit)
#   Sorted newest-first.


@app.route("/api/inventory/history/<int:product_id>", methods=["GET"])
def api_inventory_history(product_id):
    """
    Return the stock movement history for a product.

    Query params:
        limit  — max rows to return (default 50, max 200)

    Each row:
    {
      "date":        "2026-04-01 14:22:00",
      "type":        "sale" | "restock" | "adjustment",
      "delta":       -2,
      "stock_after": 18,
      "reference":   "TXN #42" | "Manual" | "Bulk action",
      "note":        "..."
    }
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        limit = min(int(request.args.get("limit", 50) or 50), 200)
    except (TypeError, ValueError):
        limit = 50

    try:
        cur = mysql.connection.cursor(DictCursor)

        # ── Verify product exists ──────────────────────────────────────────────
        cur.execute(
            "SELECT product_id, name, stock, unit FROM products WHERE product_id = %s LIMIT 1",
            (product_id,),
        )
        product = cur.fetchone()
        if not product:
            cur.close()
            return jsonify({"success": False, "message": "Product not found"}), 404

        history = []

        # ── 1. Sales deductions from transaction_items ────────────────────────
        cur.execute(
            """
            SELECT
                t.created_at                    AS event_date,
                ti.quantity                     AS qty_sold,
                ti.unit_price,
                t.transaction_id
            FROM transaction_items ti
            JOIN transactions t ON t.transaction_id = ti.transaction_id
            WHERE ti.product_id = %s
              AND t.status = 'completed'
            ORDER BY t.created_at DESC
            LIMIT %s
        """,
            (product_id, limit),
        )
        for row in cur.fetchall():
            history.append(
                {
                    "date": str(row["event_date"]),
                    "type": "sale",
                    "delta": -int(row["qty_sold"]),
                    "stock_after": None,  # historical reconstructed below if needed
                    "reference": f"TXN #{row['transaction_id']}",
                    "note": f"Sold {row['qty_sold']} × ₱{float(row['unit_price']):.2f}",
                }
            )

        # ── 2. Manual adjustments from inv_log (matched by product name) ──────
        cur.execute(
            """
            SELECT
                created_at  AS event_date,
                delta,
                stock_after,
                source,
                transaction_id,
                note,
                created_by
            FROM inv_log
            WHERE item_name = %s
            ORDER BY created_at DESC
            LIMIT %s
        """,
            (product["name"], limit),
        )
        for row in cur.fetchall():
            ref = (
                f"TXN #{row['transaction_id']}"
                if row.get("transaction_id")
                else (row.get("created_by") or "Manual")
            )
            history.append(
                {
                    "date": str(row["event_date"]),
                    "type": "restock" if float(row["delta"]) > 0 else "adjustment",
                    "delta": float(row["delta"]),
                    "stock_after": (
                        float(row["stock_after"])
                        if row["stock_after"] is not None
                        else None
                    ),
                    "reference": ref,
                    "note": row.get("note") or "",
                }
            )

        cur.close()

        # Sort all events newest-first
        history.sort(key=lambda e: e["date"], reverse=True)
        history = history[:limit]

        return jsonify(
            {
                "success": True,
                "product_id": product_id,
                "product_name": product["name"],
                "current_stock": int(product["stock"]),
                "unit": product["unit"],
                "history": history,
            }
        )

    except Exception as exc:
        app.logger.error(f"[inventory] history product #{product_id}: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/sales/summary ────────────────────────────────────────────────────
# Quick summary card data for the admin sales page.


@app.route("/api/sales/summary", methods=["GET"])
def api_sales_summary():
    """
    Return high-level sales summary for the admin sales dashboard.
    Accepts optional ?period=today|week|month (default: today).
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    period = (request.args.get("period") or "today").strip().lower()
    period_map = {
        "today": "DATE(created_at) = CURDATE()",
        "week": "YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1)",
        "month": "MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())",
    }
    where_period = period_map.get(period, period_map["today"])

    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            f"""
            SELECT
                COUNT(*)                        AS transaction_count,
                COALESCE(SUM(total_amount), 0)  AS gross_revenue,
                COALESCE(SUM(discount_amount), 0) AS total_discounts,
                COALESCE(AVG(total_amount), 0)  AS avg_order_value,
                SUM(CASE WHEN payment_method = 'cash' THEN 1 ELSE 0 END)   AS cash_count,
                SUM(CASE WHEN payment_method != 'cash' THEN 1 ELSE 0 END)  AS digital_count
            FROM transactions
            WHERE {where_period} AND status = 'completed'
        """
        )
        row = cur.fetchone()

        # Top product for the period
        cur.execute(
            f"""
            SELECT ti.product_name, SUM(ti.quantity) AS units
            FROM transaction_items ti
            JOIN transactions t ON t.transaction_id = ti.transaction_id
            WHERE {where_period} AND t.status = 'completed'
            GROUP BY ti.product_name
            ORDER BY units DESC
            LIMIT 1
        """
        )
        top = cur.fetchone()
        cur.close()

        return jsonify(
            {
                "success": True,
                "period": period,
                "transaction_count": int(row["transaction_count"] or 0),
                "gross_revenue": float(row["gross_revenue"] or 0),
                "total_discounts": float(row["total_discounts"] or 0),
                "avg_order_value": round(float(row["avg_order_value"] or 0), 2),
                "cash_count": int(row["cash_count"] or 0),
                "digital_count": int(row["digital_count"] or 0),
                "top_product": top["product_name"] if top else None,
                "top_product_units": int(top["units"]) if top else 0,
            }
        )
    except Exception as exc:
        app.logger.error(f"[sales] api_sales_summary: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/sales/top_products ───────────────────────────────────────────────


@app.route("/api/sales/top_products", methods=["GET"])
def api_sales_top_products():
    """
    Return top-selling products ranked by units sold.
    Accepts ?start=YYYY-MM-DD&end=YYYY-MM-DD&limit=N.
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    start = request.args.get("start")
    end = request.args.get("end")
    try:
        limit = min(int(request.args.get("limit", 10) or 10), 50)
    except (TypeError, ValueError):
        limit = 10

    try:
        cur = mysql.connection.cursor(DictCursor)
        params = []
        where = ["t.status = 'completed'"]
        if start and end:
            where.append("DATE(t.created_at) BETWEEN %s AND %s")
            params += [start, end]

        cur.execute(
            f"""
            SELECT
                ti.product_name      AS name,
                ti.category_name     AS category,
                SUM(ti.quantity)     AS units_sold,
                SUM(ti.line_total)   AS revenue
            FROM transaction_items ti
            JOIN transactions t ON t.transaction_id = ti.transaction_id
            WHERE {' AND '.join(where)}
            GROUP BY ti.product_name, ti.category_name
            ORDER BY units_sold DESC
            LIMIT %s
        """,
            params + [limit],
        )
        rows = cur.fetchall()
        cur.close()

        return jsonify(
            {
                "success": True,
                "products": [
                    {
                        "name": r["name"],
                        "category": r["category"] or "—",
                        "units_sold": int(r["units_sold"]),
                        "revenue": float(r["revenue"]),
                    }
                    for r in rows
                ],
            }
        )
    except Exception as exc:
        app.logger.error(f"[sales] top_products: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ── GET /api/dashboard/stats ──────────────────────────────────────────────────
# Live stats polling used by the dashboard JS (low-stock badge, sales cards).


@app.route("/api/dashboard/stats", methods=["GET"])
def api_dashboard_stats():
    """
    Return live dashboard statistics in one call to minimise round-trips.
    Used for periodic auto-refresh by the dashboard frontend.
    """
    if session.get("role") not in ["admin", "manager"]:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        cur = mysql.connection.cursor(DictCursor)

        # Today sales
        cur.execute(
            """
            SELECT
                COALESCE(SUM(total_amount), 0) AS today_total,
                COUNT(*)                        AS today_count
            FROM transactions
            WHERE DATE(created_at) = CURDATE() AND status = 'completed'
        """
        )
        sales_row = cur.fetchone()

        # Low-stock count
        cur.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM products
            WHERE is_active = 1 AND stock <= reorder_point
        """
        )
        ls_row = cur.fetchone()

        cur.close()

        return jsonify(
            {
                "success": True,
                "today_sales": float(sales_row["today_total"] or 0),
                "transaction_count": int(sales_row["today_count"] or 0),
                "low_stock_count": int(ls_row["cnt"] or 0),
            }
        )
    except Exception as exc:
        app.logger.error(f"[dashboard] api_dashboard_stats: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                            ENTRY POINT                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝



# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║               POST /api/admin/change_password  — admin password change       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/api/admin/change_password", methods=["POST"])
def api_admin_change_password():
    """
    Allow the logged-in admin to change their own password.
    Requires JSON body: { current_password, new_password, confirm_password }
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    current_pw = (data.get("current_password") or "").strip()
    new_pw     = (data.get("new_password")      or "").strip()
    confirm_pw = (data.get("confirm_password")  or "").strip()

    if not current_pw or not new_pw or not confirm_pw:
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if new_pw != confirm_pw:
        return jsonify({"success": False, "message": "New passwords do not match."}), 400
    if len(new_pw) < 8:
        return jsonify({"success": False, "message": "New password must be at least 8 characters."}), 400

    admin_id = session.get("admin_id") or session.get("user_id")
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute(
            "SELECT admin_id, password, password_hash FROM admins WHERE admin_id = %s",
            (admin_id,),
        )
        admin = cur.fetchone()
        if not admin:
            cur.close()
            return jsonify({"success": False, "message": "Admin account not found."}), 404

        if not _check_login_password(current_pw, admin):
            cur.close()
            return jsonify({"success": False, "message": "Current password is incorrect."}), 403

        new_hash = hash_password(new_pw)
        cur.execute(
            "UPDATE admins SET password_hash = %s WHERE admin_id = %s",
            (new_hash, admin_id),
        )
        mysql.connection.commit()
        cur.close()
        app.logger.info(f"[admin] Password changed for admin #{admin_id}")
        return jsonify({"success": True, "message": "Password updated successfully."})

    except Exception as exc:
        app.logger.error(f"[admin] change_password error: {exc}")
        return jsonify({"success": False, "message": "Server error — please try again."}), 500


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║          GET /api/sales/export  — download transactions as CSV               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@app.route("/api/sales/export", methods=["GET"])
def api_sales_export():
    """
    Stream a CSV download of completed transactions.
    Query params: start (YYYY-MM-DD), end (YYYY-MM-DD)  — both optional.
    Filename: transactions_YYYYMMDD_YYYYMMDD.csv
    """
    if not is_admin():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    start_date = request.args.get("start")
    end_date   = request.args.get("end")

    try:
        cur = mysql.connection.cursor(DictCursor)
        params = []
        where  = ["t.status = 'completed'"]

        if start_date and end_date:
            where.append("DATE(t.created_at) BETWEEN %s AND %s")
            params += [start_date, end_date]
        elif start_date:
            where.append("DATE(t.created_at) >= %s")
            params.append(start_date)
        elif end_date:
            where.append("DATE(t.created_at) <= %s")
            params.append(end_date)

        cur.execute(
            f"""
            SELECT
                t.transaction_id,
                t.created_at,
                t.cashier_name,
                t.payment_method,
                COALESCE(t.discount_type, 'none')                               AS discount_type,
                t.subtotal,
                t.discount_amount,
                COALESCE(t.net_sales,  ROUND(t.total_amount / 1.12, 2))         AS net_sales,
                COALESCE(t.vat_amount, ROUND(t.total_amount / 1.12 * 0.12, 2))  AS vat_amount,
                t.total_amount,
                t.amount_tendered,
                t.change_amount,
                t.note
            FROM transactions t
            WHERE {' AND '.join(where)}
            ORDER BY t.created_at DESC
            """,
            params,
        )
        rows = cur.fetchall()
        cur.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Transaction ID", "Date/Time", "Cashier", "Payment Method",
            "Discount Type", "Subtotal", "Discount Amount",
            "Net Sales (ex-VAT)", "VAT (12%)", "Total Amount",
            "Amount Tendered", "Change", "Note",
        ])
        for r in rows:
            writer.writerow([
                r["transaction_id"],
                str(r["created_at"]),
                r["cashier_name"],
                r["payment_method"],
                r["discount_type"],
                f"{float(r['subtotal']):.2f}",
                f"{float(r['discount_amount']):.2f}",
                f"{float(r['net_sales']):.2f}",
                f"{float(r['vat_amount']):.2f}",
                f"{float(r['total_amount']):.2f}",
                f"{float(r['amount_tendered']):.2f}",
                f"{float(r['change_amount']):.2f}",
                r["note"] or "",
            ])

        s = start_date.replace("-", "") if start_date else "all"
        e = end_date.replace("-", "")   if end_date   else "all"
        filename = f"transactions_{s}_{e}.csv"

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except Exception as exc:
        app.logger.error(f"[sales] export CSV error: {exc}")
        return jsonify({"success": False, "message": str(exc)}), 500


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                            ENTRY POINT                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
if __name__ == "__main__":
    # ── debug=False prevents TensorFlow/Keras exceptions from being re-raised
    # ── as fatal errors by Werkzeug's debug handler, which was killing the
    # ── server during DeepFace embedding calls.
    app.run(debug=False, use_reloader=False, threaded=True)