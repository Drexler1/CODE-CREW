from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_mysqldb import MySQL
from MySQLdb.cursors import DictCursor
from deepface import DeepFace
from datetime import datetime
import base64, cv2, os, numpy as np, time

app = Flask(__name__)
app.secret_key = 'SecretKey'

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
                    'embeddings': [],
                    'best_face':  None,
                    'started':    time.time()
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

            # ── Keep best face image (first good crop) ──────────────────────
            if sess['best_face'] is None:
                face_crop = img[y:y + h, x:x + w]
                sess['best_face'] = cv2.resize(face_crop, (160, 160))

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
    Finalize registration: average the captured embeddings, save the best face
    image, and update the employee record in the database.

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

    # ── Save face image ─────────────────────────────────────────────────────
    filename    = f"{employee_id}.jpg"
    image_path  = os.path.join(UPLOAD_FOLDER, filename)
    cv2.imwrite(image_path, sess['best_face'])
    face_path   = f"face_images/{filename}"

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

    # ── Warm the embedding cache immediately ────────────────────────────────
    avg_emb = np.mean(sess['embeddings'], axis=0).tolist()
    embedding_cache[str(employee_id)] = avg_emb

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

    # ── Liveness challenge (head-nod: up → down) ─────────────────────────────
    if employee_id not in liveness_sessions:
        reset_liveness(employee_id)

    s = liveness_sessions[employee_id]

    # Expire challenge after 20 s (was 15 – gives more time to complete nod)
    if (now - s["start_time"]).seconds > 20:
        reset_liveness(employee_id)
        return jsonify({'success': False, 'message': '⏱️ Challenge expired – look at camera and try again'})

    center_y = y + h // 2

    if s["last_y"] is None:
        s["last_y"] = center_y
        return jsonify({'success': False, 'message': '⬆️ Please move your head UP slowly'})

    move = center_y - s["last_y"]   # negative = moved up, positive = moved down

    # Anti-photo: reject if face has been perfectly static for >6 frames
    if abs(move) < 3:
        s["stable"] += 1
    else:
        s["stable"] = 0

    if s["stable"] > 6:
        return jsonify({'success': False, 'message': '🚫 Static image detected – please move your head'})

    # ── Always update last_y so movement is measured frame-to-frame ─────────
    s["last_y"] = center_y

    if s["step"] == "center":
        if move < -8:           # head moved UP (center_y decreased)
            s["step"] = "up"
            return jsonify({'success': False, 'message': '⬇️ Good! Now move your head DOWN'})
        return jsonify({'success': False, 'message': '⬆️ Move your head UP'})

    elif s["step"] == "up":
        if move > 8:            # head moved back DOWN
            s["passed"] = True

    if not s["passed"]:
        return jsonify({'success': False, 'message': '⬇️ Keep moving your head DOWN'})

    # ── Liveness passed → perform face match ────────────────────────────────
    try:
        captured_emb = extract_embedding(img, x, y, w, h)
    except Exception as e:
        return jsonify({'success': False, 'message': f'Embedding error: {e}'})

    # ── Load (or cache) the registered embedding ─────────────────────────────
    if employee_id not in embedding_cache:
        reg_path = os.path.join("static", emp['face_image_path'])
        if not os.path.exists(reg_path):
            return jsonify({'success': False, 'message': 'Registered face image not found on server'})
        try:
            # ── Read the saved face image via OpenCV ─────────────────────────
            # DeepFace.represent() with detector_backend="skip" expects a
            # pre-cropped face image.  The saved file is already a 160×160
            # face crop.  We read it with cv2.imread and resize to be safe.
            reg_img = cv2.imread(reg_path)
            if reg_img is None:
                return jsonify({'success': False, 'message': 'Could not read registered face image'})
            reg_img = cv2.resize(reg_img, (160, 160))

            reg_result = DeepFace.represent(
                img_path          = reg_img,
                model_name        = "Facenet512",
                detector_backend  = "skip",
                enforce_detection = False
            )
            embedding_cache[employee_id] = reg_result[0]["embedding"]
        except Exception as e:
            return jsonify({'success': False, 'message': f'Could not process registered face: {e}'})

    registered_emb = embedding_cache[employee_id]
    distance = cosine_distance(captured_emb, registered_emb)

    last_frame_time[employee_id] = now

    # Threshold: ≥0.45 cosine distance = different person (raised from 0.40 to accommodate
    # real-world webcam quality variation between registration and verification frames)
    if distance >= 0.45:
        reset_liveness(employee_id)
        return jsonify({'success': False, 'message': f'❌ Face not matched (score: {distance:.3f})'})

    reset_liveness(employee_id)
    return jsonify({'success': True, 'message': f'✅ Identity verified (score: {distance:.3f})'})


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

        cur = mysql.connection.cursor(DictCursor)

        # ── Legacy admin tab (kept for backwards compat; hidden in UI) ───────
        if role == 'admin':
            cur.execute(
                "SELECT * FROM admins WHERE TRIM(username)=%s AND TRIM(password)=%s",
                (username, password)
            )
            user = cur.fetchone()
            if user:
                session.clear()
                session['admin_id']  = user['admin_id']
                session['role']      = 'admin'
                session['is_admin']  = True
                session['full_name'] = (user.get('full_name') or 'Admin').strip()
                cur.close()
                return redirect(url_for('dashboard'))

        # ── Manager tab: check employees first, then admins table ────────────
        elif role == 'manager':

            # 1. Try a regular manager employee account
            cur.execute(
                """SELECT * FROM employees
                   WHERE TRIM(username)=%s AND TRIM(password)=%s
                   AND role='manager' AND employment_status='active'""",
                (username, password)
            )
            employee = cur.fetchone()

            if employee:
                session.clear()
                session['employee_id'] = employee['employee_id']
                session['role']        = 'manager'
                session['is_admin']    = False
                session['full_name']   = (employee.get('full_name') or 'Manager').strip()
                cur.execute(
                    "UPDATE employees SET last_login=NOW() WHERE employee_id=%s",
                    (employee['employee_id'],)
                )
                mysql.connection.commit()
                cur.close()
                return redirect(url_for('dashboard'))

            # 2. No manager employee matched — try the admins table
            #    This lets admins log in through the (now only visible) Manager tab
            cur.execute(
                "SELECT * FROM admins WHERE TRIM(username)=%s AND TRIM(password)=%s",
                (username, password)
            )
            admin = cur.fetchone()

            if admin:
                session.clear()
                session['admin_id']  = admin['admin_id']
                session['role']      = 'admin'
                session['is_admin']  = True
                session['full_name'] = (admin.get('full_name') or 'Admin').strip()
                cur.close()
                return redirect(url_for('dashboard'))

        # ── Cashier tab ───────────────────────────────────────────────────────
        elif role == 'cashier':
            cur.execute(
                """SELECT * FROM employees
                   WHERE TRIM(username)=%s AND TRIM(password)=%s
                   AND role='cashier' AND employment_status='active'""",
                (username, password)
            )
            user = cur.fetchone()
            if user:
                session.clear()
                session['employee_id'] = user['employee_id']
                session['role']        = 'cashier'
                session['is_admin']    = False
                session['full_name']   = (user.get('full_name') or 'Cashier').strip()
                cur.execute(
                    "UPDATE employees SET last_login=NOW() WHERE employee_id=%s",
                    (user['employee_id'],)
                )
                mysql.connection.commit()
                cur.close()
                return redirect(url_for('cashier_dashboard'))

        flash("Invalid credentials. Please check your username and password.")
        cur.close()

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
        else:
            cur.execute("SELECT full_name FROM employees WHERE employee_id=%s", (session['employee_id'],))
        user      = cur.fetchone()
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
    else:
        cur.execute("SELECT full_name FROM employees WHERE employee_id=%s", (session['employee_id'],))
    user      = cur.fetchone()
    full_name = user['full_name'] if user else session['role'].capitalize()

    cur.execute("""
        SELECT employee_id, full_name, username, role, contact_number,
               employment_status, face_image_path, face_model_path,
               last_login, created_at
        FROM employees
        ORDER BY created_at DESC
    """)
    employees = cur.fetchall()
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

    if not all([full_name, username, password, role, contact]):
        return jsonify({'success': False, 'message': 'All fields are required'})

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """INSERT INTO employees (full_name, username, password, role, contact_number, employment_status)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (full_name, username, password, role, contact, status)
        )
        employee_id = cur.lastrowid

        # ── Process uploaded face frames ─────────────────────────────────────
        files      = request.files.getlist('face_images[]')
        embeddings = []
        best_face  = None

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
                if best_face is None:
                    crop      = img[y:y + h, x:x + w]
                    best_face = cv2.resize(crop, (160, 160))
            except (ValueError, Exception):
                continue

        if len(embeddings) < 1:
            mysql.connection.rollback()
            cur.close()
            return jsonify({'success': False, 'message': 'No face detected in captured frames – please retake'})

        # ── Save best face image ─────────────────────────────────────────────
        filename   = f"{employee_id}.jpg"
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        cv2.imwrite(image_path, best_face)
        face_path  = f"face_images/{filename}"

        cur.execute(
            "UPDATE employees SET face_image_path=%s WHERE employee_id=%s",
            (face_path, employee_id)
        )
        mysql.connection.commit()
        cur.close()

        # Warm embedding cache
        embedding_cache[str(employee_id)] = np.mean(embeddings, axis=0).tolist()

        return jsonify({'success': True, 'message': 'Employee registered with Face ID ✅'})

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
        cur = mysql.connection.cursor()

        files      = request.files.getlist('face_images[]')
        embeddings = []
        best_face  = None

        for file in files:
            file_bytes = np.frombuffer(file.read(), np.uint8)
            img        = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            if img is None:
                continue
            try:
                gray     = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                x, y, w, h = detect_face_strict(img, gray)
                emb      = extract_embedding(img, x, y, w, h)
                embeddings.append(emb)
                if best_face is None:
                    crop      = img[y:y + h, x:x + w]
                    best_face = cv2.resize(crop, (160, 160))
            except (ValueError, Exception):
                continue

        if embeddings and best_face is not None:
            # New face registered during edit
            filename   = f"{employee_id}.jpg"
            image_path = os.path.join(UPLOAD_FOLDER, filename)
            cv2.imwrite(image_path, best_face)
            face_path  = f"face_images/{filename}"

            cur.execute(
                """UPDATE employees
                   SET full_name=%s, username=%s, role=%s, contact_number=%s,
                       employment_status=%s, face_image_path=%s
                   WHERE employee_id=%s""",
                (full_name, username, role, contact, status, face_path, employee_id)
            )
            # Invalidate and re-warm cache
            embedding_cache[str(employee_id)] = np.mean(embeddings, axis=0).tolist()
        else:
            cur.execute(
                """UPDATE employees
                   SET full_name=%s, username=%s, role=%s, contact_number=%s,
                       employment_status=%s
                   WHERE employee_id=%s""",
                (full_name, username, role, contact, status, employee_id)
            )

        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/delete_employee/<int:employee_id>', methods=['DELETE'])
def delete_employee(employee_id):
    """Soft-delete (set inactive) an employee."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE employees SET employment_status='inactive', disabled_at=NOW() WHERE employee_id=%s",
            (employee_id,)
        )
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})
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
    else:
        cur.execute("SELECT full_name FROM employees WHERE employee_id=%s", (session['employee_id'],))
    user      = cur.fetchone()
    full_name = user['full_name'] if user else session['role'].capitalize()
    cur.close()

    return render_template('staff_attendance.html', full_name=full_name)


@app.route('/log_attendance', methods=['POST'])
def log_attendance():
    """
    Record a clock-in or clock-out after face verification has already succeeded.

    POST JSON:
        { "employee_id": int, "action": "clock_in"|"clock_out", "shift_type": str }
    """
    if 'employee_id' not in session and not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data       = request.get_json(silent=True) or {}
    action     = data.get('action')
    shift_type = data.get('shift_type')
    employee_id = session.get('employee_id') or data.get('employee_id')

    if not all([employee_id, action, shift_type]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400

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
            END AS fulfill_working_hours
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

    return jsonify({'success': True, 'date': str(dt), 'records': rows})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         ADMIN SETTINGS                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@app.route('/admin_settings')
def admin_settings():
    if not is_admin():
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT full_name FROM admins WHERE admin_id=%s", (session['admin_id'],))
    admin     = cur.fetchone()
    full_name = admin['full_name'] if admin else "Admin"
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
    employee = cur.fetchone()
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
# ║                            ENTRY POINT                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

if __name__ == '__main__':
    # ── debug=False prevents TensorFlow/Keras exceptions from being re-raised
    # ── as fatal errors by Werkzeug's debug handler, which was killing the
    # ── server during DeepFace embedding calls.
    app.run(debug=False, use_reloader=False)