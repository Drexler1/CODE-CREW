"""
migrate_encrypt.py  —  AES-256 migration (run once)
Encrypts username, password, full_name, contact_number in employees + admins.
Also adds/populates username_hash column using SHA-256(AES_KEY + username)
for secure login lookups — no separate HMAC key required.
Safe to re-run — already-encrypted rows are skipped automatically.
"""
import os, base64, hashlib
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


conn = MySQLdb.connect(
    host='localhost', user='root', passwd='', db='pos_system', charset='utf8mb4'
)
cur = conn.cursor(MySQLdb.cursors.DictCursor)

print("=" * 60)
print("AES-256 Migration — encrypting all PII fields")
print("username_hash = SHA-256(AES_KEY + username)  [no HMAC key]")
print("=" * 60)

# ── Ensure username_hash columns exist ──────────────────────────────────────
for tbl in ('employees', 'admins'):
    try:
        cur.execute(
            f"ALTER TABLE `{tbl}` ADD COLUMN `username_hash` VARCHAR(64) DEFAULT NULL"
        )
        conn.commit()
        print(f"Added username_hash to {tbl}")
    except Exception:
        print(f"username_hash already exists in {tbl}")

# ── employees ────────────────────────────────────────────────────────────────
print("\n[1/2] employees...")
cur.execute(
    "SELECT employee_id, username, full_name, password, contact_number FROM employees"
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
        print(f"  ⏭  Employee #{eid} — already encrypted")

# ── admins ───────────────────────────────────────────────────────────────────
print("\n[2/2] admins...")
cur.execute("SELECT admin_id, username, full_name, password FROM admins")
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
        print(f"  ⏭  Admin #{aid} — already encrypted")

conn.commit()
cur.close()
conn.close()
print(f"\nDone. employees={n}, admins={m}")
print("⚠️  Keep AES_SECRET_KEY identical in app.py and this script!")