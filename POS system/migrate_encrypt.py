import os, base64, hashlib
import bcrypt
import MySQLdb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ── Single key: AES_SECRET_KEY drives both encryption and username hashing ──
_AES_RAW = os.environ.get('AES_SECRET_KEY', 'change-this-aes-key-before-deploy!')
AES_KEY  = hashlib.sha256(_AES_RAW.encode()).digest()   # 32 bytes


# ═══════════════════════════ Core AES helpers ════════════════════════════════

def aes_encrypt(p: str) -> str:
    """AES-256-CBC encrypt *p*; return base-64(IV + ciphertext)."""
    if not p:
        return p
    iv = os.urandom(16)
    ct = AES.new(AES_KEY, AES.MODE_CBC, iv).encrypt(pad(p.encode(), AES.block_size))
    return base64.b64encode(iv + ct).decode()


def aes_decrypt(t: str):
    """Decrypt a value produced by aes_encrypt; return plaintext or None."""
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


def is_enc(v: str) -> bool:
    """Return True if *v* is already AES-encrypted (i.e. decryptable)."""
    return v is not None and aes_decrypt(str(v)) is not None


def aes_username_hash(u: str) -> str:
    """Deterministic SHA-256(AES_KEY || username) for the username_hash column."""
    return hashlib.sha256(AES_KEY + u.strip().lower().encode()).hexdigest()


# ═══════════════════════════ bcrypt helpers ══════════════════════════════════

BCRYPT_ROUNDS = 12


def bcrypt_hash(plaintext: str) -> str:
    return bcrypt.hashpw(
        plaintext.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS)
    ).decode('utf-8')


def is_bcrypt_hash(v: str) -> bool:
    return bool(v and (v.startswith('$2b$') or v.startswith('$2a$')))


# ═══════════════════════════ DB connection ═══════════════════════════════════

conn = MySQLdb.connect(
    host='localhost', user='root', passwd='', db='pos_system', charset='utf8mb4'
)
cur = conn.cursor(MySQLdb.cursors.DictCursor)

print("=" * 70)
print("AES-256 Migration")
print("  employees / admins  — PII + password + hourly_rate fields")
print("  attendance          — shift_type, numeric payroll columns")
print("  payroll_periods     — notes, financial summary columns")
print("=" * 70)


# ═════════════════════════════════════════════════════════════════════════════
# STEP 0 — Schema: ensure all helper columns exist and numeric columns are
#           widened to VARCHAR so they can hold ciphertext.
# ═════════════════════════════════════════════════════════════════════════════

def _add_column(table: str, col: str, defn: str):
    try:
        cur.execute(f"ALTER TABLE `{table}` ADD COLUMN `{col}` {defn}")
        conn.commit()
        print(f"  + Added {table}.{col}")
    except Exception:
        pass   # column already exists


def _modify_column(table: str, col: str, new_defn: str):
    """Widen a numeric column to VARCHAR so it can hold base-64 ciphertext."""
    try:
        cur.execute(f"ALTER TABLE `{table}` MODIFY COLUMN `{col}` {new_defn}")
        conn.commit()
        print(f"  ~ Widened {table}.{col} → {new_defn}")
    except Exception as e:
        print(f"  ! Could not modify {table}.{col}: {e}")


print("\n[STEP 0] Schema adjustments …")

# employees / admins — hash columns
for tbl in ('employees', 'admins'):
    _add_column(tbl, 'username_hash', 'VARCHAR(64) DEFAULT NULL')
    _add_column(tbl, 'password_hash', 'VARCHAR(255) DEFAULT NULL')

# employees — widen hourly_rate DECIMAL → VARCHAR for encryption
_modify_column('employees', 'hourly_rate', 'VARCHAR(128) NOT NULL DEFAULT \'\'')

# attendance — widen numeric payroll columns to TEXT (encrypted values are ~64 chars)
#   shift_type is already VARCHAR(50) — expand to 128 for safety
_modify_column('attendance', 'shift_type',            'VARCHAR(128) DEFAULT NULL')
_modify_column('attendance', 'hours_worked',          'VARCHAR(128) DEFAULT NULL')
_modify_column('attendance', 'hourly_rate_snapshot',  'VARCHAR(128) DEFAULT NULL')
_modify_column('attendance', 'daily_earnings',        'VARCHAR(128) DEFAULT NULL')
# daily_pay is a nullable column — also widen
_modify_column('attendance', 'daily_pay',             'VARCHAR(128) DEFAULT NULL')

# payroll_periods — notes is already TEXT; widen financial columns
_modify_column('payroll_periods', 'total_hours', 'VARCHAR(128) NOT NULL DEFAULT \'\'')
_modify_column('payroll_periods', 'total_pay',   'VARCHAR(128) NOT NULL DEFAULT \'\'')


# ═════════════════════════════════════════════════════════════════════════════
# STEP 1 — employees
# ═════════════════════════════════════════════════════════════════════════════

print("\n[STEP 1/4] employees …")
cur.execute(
    "SELECT employee_id, username, full_name, password, password_hash, "
    "contact_number, hourly_rate FROM employees"
)
n = 0
for row in cur.fetchall():
    eid = row['employee_id']
    upd = {}

    # Encrypt PII text fields
    for f in ('username', 'full_name', 'password', 'contact_number'):
        v = row.get(f)
        if v and not is_enc(str(v)):
            upd[f] = aes_encrypt(str(v).strip())

    # hourly_rate — compensation data; stored as VARCHAR after schema widening
    hr = row.get('hourly_rate')
    if hr is not None:
        hr_str = str(hr).strip()
        if hr_str not in ('0', '0.00', '') and not is_enc(hr_str):
            upd['hourly_rate'] = aes_encrypt(hr_str)

    # username_hash
    raw_u = row.get('username', '')
    if raw_u and not is_enc(raw_u):
        upd['username_hash'] = aes_username_hash(raw_u.strip())

    # bcrypt password_hash
    existing_hash = row.get('password_hash') or ''
    if not is_bcrypt_hash(existing_hash):
        enc_pw = upd.get('password') or row.get('password') or ''
        plaintext_pw = aes_decrypt(enc_pw) if enc_pw else None
        if plaintext_pw:
            upd['password_hash'] = bcrypt_hash(plaintext_pw)

    if upd:
        sql = (
            "UPDATE employees SET "
            + ", ".join(f"`{k}`=%s" for k in upd)
            + " WHERE employee_id=%s"
        )
        cur.execute(sql, list(upd.values()) + [eid])
        n += 1
        print(f"  ✅ Employee #{eid} — {list(upd.keys())}")
    else:
        print(f"  ⏭  Employee #{eid} — already encrypted & hashed")

conn.commit()


# ═════════════════════════════════════════════════════════════════════════════
# STEP 2 — admins
# ═════════════════════════════════════════════════════════════════════════════

print("\n[STEP 2/4] admins …")
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

    existing_hash = row.get('password_hash') or ''
    if not is_bcrypt_hash(existing_hash):
        enc_pw = upd.get('password') or row.get('password') or ''
        plaintext_pw = aes_decrypt(enc_pw) if enc_pw else None
        if plaintext_pw:
            upd['password_hash'] = bcrypt_hash(plaintext_pw)

    if upd:
        sql = (
            "UPDATE admins SET "
            + ", ".join(f"`{k}`=%s" for k in upd)
            + " WHERE admin_id=%s"
        )
        cur.execute(sql, list(upd.values()) + [aid])
        m += 1
        print(f"  ✅ Admin #{aid} — {list(upd.keys())}")
    else:
        print(f"  ⏭  Admin #{aid} — already encrypted & hashed")

conn.commit()


# ═════════════════════════════════════════════════════════════════════════════
# STEP 3 — attendance
#
# Fields encrypted:
#   shift_type           — VARCHAR (already text, just encrypt value)
#   hours_worked         — was DECIMAL; now VARCHAR after schema step
#   hourly_rate_snapshot — was DECIMAL; now VARCHAR
#   daily_earnings       — was DECIMAL; now VARCHAR
#   daily_pay            — was DECIMAL; now VARCHAR
#
# Fields left in plaintext (required for SQL joins / time calculations):
#   attendance_id, employee_id, attendance_date,
#   clock_in, clock_out, created_at,
#   pay_period_start, pay_period_end
# ═════════════════════════════════════════════════════════════════════════════

print("\n[STEP 3/4] attendance …")
cur.execute(
    "SELECT attendance_id, shift_type, hours_worked, "
    "hourly_rate_snapshot, daily_earnings, daily_pay "
    "FROM attendance"
)
att_rows = cur.fetchall()
a_count = 0

for row in att_rows:
    aid  = row['attendance_id']
    upd  = {}

    # shift_type (text)
    st = row.get('shift_type')
    if st and not is_enc(str(st)):
        upd['shift_type'] = aes_encrypt(str(st).strip())

    # Numeric fields — stored as string after column widening;
    # only encrypt if the value is non-zero/non-null and not already encrypted.
    for field in ('hours_worked', 'hourly_rate_snapshot', 'daily_earnings', 'daily_pay'):
        raw = row.get(field)
        if raw is None:
            continue
        raw_str = str(raw).strip()
        # Skip zero-value defaults and already-encrypted values
        if raw_str in ('0', '0.00', '0.0000', ''):
            continue
        if not is_enc(raw_str):
            upd[field] = aes_encrypt(raw_str)

    if upd:
        sql = (
            "UPDATE attendance SET "
            + ", ".join(f"`{k}`=%s" for k in upd)
            + " WHERE attendance_id=%s"
        )
        cur.execute(sql, list(upd.values()) + [aid])
        a_count += 1
        print(f"  ✅ Attendance #{aid} — {list(upd.keys())}")
    else:
        print(f"  ⏭  Attendance #{aid} — already encrypted or no PII")

conn.commit()


# ═════════════════════════════════════════════════════════════════════════════
# STEP 4 — payroll_periods
#
# Fields encrypted:
#   notes       — free-text admin notes (nullable TEXT)
#   total_pay   — financial summary value; widened to VARCHAR
#   total_hours — financial summary value; widened to VARCHAR
#
# Fields left in plaintext:
#   payroll_id, employee_id, period_start, period_end,
#   days_worked, status, generated_at, finalized_at
#   (all needed for lookups, ordering, and status checks)
# ═════════════════════════════════════════════════════════════════════════════

print("\n[STEP 4/4] payroll_periods …")
cur.execute(
    "SELECT payroll_id, notes, total_pay, total_hours FROM payroll_periods"
)
pp_rows = cur.fetchall()
p_count = 0

for row in pp_rows:
    pid = row['payroll_id']
    upd = {}

    # notes (nullable free-text)
    notes = row.get('notes')
    if notes and not is_enc(str(notes)):
        upd['notes'] = aes_encrypt(str(notes).strip())

    # total_pay
    tp = row.get('total_pay')
    if tp is not None:
        tp_str = str(tp).strip()
        if tp_str not in ('0', '0.00', '') and not is_enc(tp_str):
            upd['total_pay'] = aes_encrypt(tp_str)

    # total_hours
    th = row.get('total_hours')
    if th is not None:
        th_str = str(th).strip()
        if th_str not in ('0', '0.00', '') and not is_enc(th_str):
            upd['total_hours'] = aes_encrypt(th_str)

    if upd:
        sql = (
            "UPDATE payroll_periods SET "
            + ", ".join(f"`{k}`=%s" for k in upd)
            + " WHERE payroll_id=%s"
        )
        cur.execute(sql, list(upd.values()) + [pid])
        p_count += 1
        print(f"  ✅ PayrollPeriod #{pid} — {list(upd.keys())}")
    else:
        print(f"  ⏭  PayrollPeriod #{pid} — already encrypted or no data")

conn.commit()


# ═════════════════════════════════════════════════════════════════════════════
# STEP 5 — login_attempts table (idempotent, no data to encrypt)
# ═════════════════════════════════════════════════════════════════════════════

print("\n[STEP 5/5] login_attempts table …")
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

cur.close()
conn.close()

print(f"""
╔══════════════════════════════════════════════════════════════╗
║  Migration complete                                          ║
╠══════════════════════════════════════════════════════════════╣
║  employees updated      : {n:<34}║
║  admins updated         : {m:<34}║
║  attendance rows updated: {a_count:<34}║
║  payroll_periods updated: {p_count:<34}║
╚══════════════════════════════════════════════════════════════╝

⚠️  Keep AES_SECRET_KEY identical in app.py and this script!
⚠️  employees.hourly_rate is now VARCHAR — app.py must call
    aes_decrypt(hourly_rate) and cast to float before any arithmetic.
⚠️  app.py must call aes_decrypt() when reading attendance /
    payroll_periods numeric fields — raw SQL aggregates (SUM,
    AVG, etc.) will no longer work on those columns directly.
""")