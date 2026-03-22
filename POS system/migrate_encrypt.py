"""
migrate_encrypt.py  —  AES-256 migration + bcrypt password hashing (run once)
Encrypts username, password, full_name, contact_number in employees + admins.
Also adds/populates username_hash column using SHA-256(AES_KEY + username)
for secure login lookups — no separate HMAC key required.
Adds password_hash column and populates it with bcrypt(12) hashes derived from
the AES-decrypted plaintext passwords.
Safe to re-run — already-encrypted / already-hashed rows are skipped automatically.
"""
import os, base64, hashlib
import bcrypt
import MySQLdb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ── Single key: AES_SECRET_KEY drives both encryption and username hashing ──
_AES_RAW = os.environ.get('AES_SECRET_KEY', 'change-this-aes-key-before-deploy!')
AES_KEY  = hashlib.sha256(_AES_RAW.encode()).digest()   # 32 bytes


def aes_encrypt(p):
    if not p:
        return p
    iv = os.urandom(16)
    ct = AES.new(AES_KEY, AES.MODE_CBC, iv).encrypt(pad(p.encode(), AES.block_size))
    return base64.b64encode(iv + ct).decode()


def aes_decrypt(t):
    if not t:
        return None
    try:
        raw = base64.b64decode(t)
        return unpad(
            AES.new(AES_KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]),
            AES.block_size
        ).decode()
    except Exception:
        return None


def is_enc(v):
    """Return True if the value is already AES-encrypted (decryptable)."""
    return v is not None and aes_decrypt(str(v)) is not None


def aes_username_hash(u):
    """Deterministic SHA-256(AES_KEY + username) for username_hash column."""
    return hashlib.sha256(AES_KEY + u.strip().lower().encode()).hexdigest()


BCRYPT_ROUNDS = 12


def bcrypt_hash(plaintext: str) -> str:
    """Hash plaintext password with bcrypt work factor BCRYPT_ROUNDS."""
    return bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS)).decode('utf-8')


def is_bcrypt_hash(v: str) -> bool:
    """Return True if v looks like a bcrypt hash ($2b$ or $2a$ prefix)."""
    return bool(v and (v.startswith('$2b$') or v.startswith('$2a$')))


conn = MySQLdb.connect(
    host='localhost', user='root', passwd='', db='pos_system', charset='utf8mb4'
)
cur = conn.cursor(MySQLdb.cursors.DictCursor)

print("=" * 60)
print("AES-256 Migration — encrypting all PII fields")
print("username_hash = SHA-256(AES_KEY + username)  [no HMAC key]")
print("=" * 60)

# ── Ensure username_hash and password_hash columns exist ───────────────────────
for tbl in ('employees', 'admins'):
    try:
        cur.execute(
            f"ALTER TABLE `{tbl}` ADD COLUMN `username_hash` VARCHAR(64) DEFAULT NULL"
        )
        conn.commit()
        print(f"Added username_hash to {tbl}")
    except Exception:
        print(f"username_hash already exists in {tbl}")

    try:
        cur.execute(
            f"ALTER TABLE `{tbl}` ADD COLUMN `password_hash` VARCHAR(255) DEFAULT NULL"
        )
        conn.commit()
        print(f"Added password_hash to {tbl}")
    except Exception:
        print(f"password_hash already exists in {tbl}")

# ── employees ────────────────────────────────────────────────────────────────
print("\n[1/2] employees...")
cur.execute(
    "SELECT employee_id, username, full_name, password, password_hash, contact_number FROM employees"
)
n = 0
for row in cur.fetchall():
    eid = row['employee_id']
    upd = {}

    for f in ('username', 'full_name', 'password', 'contact_number'):
        v = row.get(f)
        if v and not is_enc(str(v)):
            upd[f] = aes_encrypt(str(v).strip())

    raw_u = row.get('username', '')
    if raw_u and not is_enc(raw_u):
        upd['username_hash'] = aes_username_hash(raw_u.strip())

    # ── bcrypt hash: derive from AES-decrypted password ──────────────────
    existing_hash = row.get('password_hash') or ''
    if not is_bcrypt_hash(existing_hash):
        enc_pw = upd.get('password') or row.get('password') or ''
        plaintext_pw = aes_decrypt(enc_pw) if enc_pw else None
        if plaintext_pw:
            upd['password_hash'] = bcrypt_hash(plaintext_pw)
            print(f"  🔒 Employee #{eid} — bcrypt hash generated")

    if upd:
        sql = (
            "UPDATE employees SET "
            + ", ".join(f"`{k}`=%s" for k in upd)
            + " WHERE employee_id=%s"
        )
        cur.execute(sql, list(upd.values()) + [eid])
        n += 1
        print(f"  ✅ Employee #{eid} — updated {list(upd.keys())}")
    else:
        print(f"  ⏭  Employee #{eid} — already encrypted & hashed")

# ── admins ───────────────────────────────────────────────────────────────────
print("\n[2/2] admins...")
cur.execute("SELECT admin_id, username, full_name, password, password_hash FROM admins")
m = 0
for row in cur.fetchall():
    aid = row['admin_id']
    upd = {}

    for f in ('username', 'full_name', 'password'):
        v = row.get(f)
        if v and not is_enc(str(v)):
            upd[f] = aes_encrypt(str(v).strip())

    raw_u = row.get('username', '')
    if raw_u and not is_enc(raw_u):
        upd['username_hash'] = aes_username_hash(raw_u.strip())

    # ── bcrypt hash: derive from AES-decrypted password ──────────────────
    existing_hash = row.get('password_hash') or ''
    if not is_bcrypt_hash(existing_hash):
        enc_pw = upd.get('password') or row.get('password') or ''
        plaintext_pw = aes_decrypt(enc_pw) if enc_pw else None
        if plaintext_pw:
            upd['password_hash'] = bcrypt_hash(plaintext_pw)
            print(f"  🔒 Admin #{aid} — bcrypt hash generated")

    if upd:
        sql = (
            "UPDATE admins SET "
            + ", ".join(f"`{k}`=%s" for k in upd)
            + " WHERE admin_id=%s"
        )
        cur.execute(sql, list(upd.values()) + [aid])
        m += 1
        print(f"  ✅ Admin #{aid} — updated {list(upd.keys())}")
    else:
        print(f"  ⏭  Admin #{aid} — already encrypted & hashed")

# ── login_attempts table ─────────────────────────────────────────────────────
print("\n[3/3] login_attempts table...")
try:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS `login_attempts` (
            `attempt_key`   VARCHAR(64)  NOT NULL,
            `fail_count`    INT          NOT NULL DEFAULT 0,
            `locked_until`  DATETIME     DEFAULT NULL,
            `last_attempt`  DATETIME     DEFAULT NULL,
            PRIMARY KEY (`attempt_key`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    conn.commit()
    print("  ✅ login_attempts table ready")
except Exception as e:
    print(f"  ⚠️  login_attempts: {e}")

conn.commit()
cur.close()
conn.close()
print(f"\nDone. employees={n}, admins={m}")
print("⚠️  Keep AES_SECRET_KEY identical in app.py and this script!")