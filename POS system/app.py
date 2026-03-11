from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_mysqldb import MySQL
from MySQLdb.cursors import DictCursor
from datetime import datetime
import base64
import cv2
import os
import numpy as np   

app = Flask(__name__)
app.secret_key = 'Books and Blooms Secret Key'



UPLOAD_FOLDER = os.path.join('static', 'face_images')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'pos_system'

mysql = MySQL(app)



# ================================ FACE RECOGNITION ================================

face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

def train_face_model(image_path, model_path):
    img = cv2.imread(image_path)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    faces = face_cascade.detectMultiScale(gray, 1.3, 5)

    if len(faces) == 0:
        return False
    
    recognizer = cv2.face.LBPHFaceRecognizer_create()

    for (x, y, w, h) in faces:
        face = gray[y:y+h, x:x+w]
        face = cv2.resize(face, (200, 200))
        recognizer.train([face], np.array([1]))
         
    recognizer.save(model_path)
    return True



@app.route('/verify_face', methods=['POST'])
def verify_face():
    data = request.get_json()

    if not data:
        return jsonify({'success': False, 'message': 'No data received'}), 400

    employee_id = data.get('employee_id')
    image_data = data.get('image')

    if not employee_id or not image_data:
        return jsonify({'success': False, 'message': 'Missing data'}), 400

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT face_model_path FROM employees WHERE employee_id = %s", (employee_id,))
    emp = cur.fetchone()
    cur.close()

    if not emp or not emp['face_model_path']:
        return jsonify({'success': False, 'message': 'No face registered'}), 400

    model_path = os.path.join("static", emp['face_model_path'])

    if not os.path.exists(model_path):
        return jsonify({'success': False, 'message': 'Face model missing'}), 400

    recognizer = cv2.face.LBPHFaceRecognizer_create()
    recognizer.read(model_path)

    try:
        img_bytes = base64.b64decode(image_data.split(",")[1])
        np_arr = np.frombuffer(img_bytes, np.uint8)
        captured_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    except:
        return jsonify({'success': False, 'message': 'Invalid image data'}), 400

    gray = cv2.cvtColor(captured_img, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, 1.3, 5)

    if len(faces) == 0:
        return jsonify({'success': False, 'message': 'No face detected'})

    for (x, y, w, h) in faces:
        face = gray[y:y+h, x:x+w]
        face = cv2.resize(face, (200, 200))

        label, confidence = recognizer.predict(face)

        # 70 is more stable than 65
        if confidence <= 70:
            return jsonify({'success': True})

    return jsonify({'success': False, 'message': 'Face not recognized'})

# ================================ LOGIN ROUTES ================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('login_role')
        username = request.form.get(f"{role}Username")
        password = request.form.get(f"{role}Password")

        cur = mysql.connection.cursor(DictCursor)

        if role == 'admin':
            cur.execute("""
                SELECT * FROM admins
                WHERE username=%s AND password=%s
            """, (username, password))

            user = cur.fetchone()

            if user:
                session.clear()
                session['admin_id'] = user['admin_id']
                session['role'] = 'admin'
                return redirect(url_for('dashboard'))

        elif role in ['manager', 'cashier']:
            cur.execute("""
                SELECT * FROM employees
                WHERE username=%s AND password=%s
                AND role=%s
                AND employment_status='active'
            """, (username, password, role))

            user = cur.fetchone()

            if user:
                session.clear()
                session['employee_id'] = user['employee_id']
                session['role'] = role

                if role == 'manager':
                    return redirect(url_for('dashboard'))
                else:
                    return redirect(url_for('cashier_dashboard'))

        flash("Invalid credentials.")
        cur.close()

    return render_template('index.html')


# ================================ ADMIN ROUTES ================================

@app.route('/dashboard')
def dashboard():
        if session.get('role') not in ['admin', 'manager']:
            return redirect(url_for('login'))

        if session['role'] == 'admin':
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT full_name FROM admins WHERE admin_id = %s", (session['admin_id'],))
            user = cur.fetchone()
            cur.close()
            full_name = user['full_name'] if user else "Admin"
        else:
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT full_name FROM employees WHERE employee_id = %s", (session['employee_id'],))
            user = cur.fetchone()
            cur.close()
            full_name = user['full_name'] if user else "Manager"

        return render_template('dashboard.html', full_name=full_name)

@app.route('/employee_management')
def employee_management():
    if session.get('role') not in ['admin', 'manager']:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(DictCursor)

    # Get full name depending on role
    if session['role'] == 'admin':
        cur.execute("SELECT full_name FROM admins WHERE admin_id = %s",
                    (session['admin_id'],))
        user = cur.fetchone()
        full_name = user['full_name'] if user else "Admin"

    else:  # manager
        cur.execute("SELECT full_name FROM employees WHERE employee_id = %s",
                    (session['employee_id'],))
        user = cur.fetchone()
        full_name = user['full_name'] if user else "Manager"

    # Get employees list
    cur.execute("""
        SELECT employee_id, full_name, username, role, contact_number,
               employment_status, face_image_path, face_model_path,
               last_login, created_at
        FROM employees
    """)
    employees = cur.fetchall()
    cur.close()

    return render_template(
        'employee_management.html',
        full_name=full_name,
        employees=employees
)

        

@app.route('/add_employee', methods=['POST'])
def add_employee():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    full_name = request.form.get('full_name')
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    contact = request.form.get('contact')
    status = request.form.get('status')
    face_file = request.files.get('face_image')

    if not all([full_name, username, password, role, contact]):
        return jsonify({'success': False, 'message': 'Missing required fields'})

    face_image_path = None
    face_model_path = None

    if face_file:
        filename = f"{username}.jpg"
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        face_file.save(image_path)

        model_folder = os.path.join("static", "face_models")
        os.makedirs(model_folder, exist_ok=True)

        model_full_path = os.path.join(model_folder, f"{username}.yml")

        if not train_face_model(image_path, model_full_path):
            return jsonify({'success': False, 'message': 'No face detected in image'})

        face_image_path = f"face_images/{username}.jpg"
        face_model_path = f"face_models/{username}.yml"

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
                INSERT INTO employees 
                (full_name, username, password, role, contact_number, employment_status,
                face_image_path, face_model_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,(full_name, username, password, role, contact, status,face_image_path, face_model_path))

        mysql.connection.commit()
        cur.close()

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# ✅ UPDATED FUNCTION (WITH FACE IMAGE UPDATE)
@app.route('/update_employee/<int:employee_id>', methods=['POST'])
def update_employee(employee_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    full_name = request.form.get('full_name')
    username = request.form.get('username')
    role = request.form.get('role')
    contact = request.form.get('contact')
    status = request.form.get('status')

    face_file = request.files.get('face_image')

    face_image_path = None
    face_model_path = None

    if face_file:
        filename = f"{username}.jpg"
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        face_file.save(image_path)

        model_folder = os.path.join("static", "face_models")
        os.makedirs(model_folder, exist_ok=True)

        model_full_path = os.path.join(model_folder, f"{username}.yml")

        if not train_face_model(image_path, model_full_path):
            return jsonify({'success': False, 'message': 'No face detected'})

        face_image_path = f"face_images/{username}.jpg"
        face_model_path = f"face_models/{username}.yml"

    try:
        cur = mysql.connection.cursor()

        if face_image_path:
            cur.execute("""
                UPDATE employees
                SET full_name=%s,
                    username=%s,
                    role=%s,
                    contact_number=%s,
                    employment_status=%s,
                    face_image_path=%s,
                    face_model_path=%s
                WHERE employee_id=%s
            """, (full_name, username, role, contact, status, face_image_path, face_model_path, employee_id))
        else:
            cur.execute("""
                UPDATE employees
                SET full_name=%s,
                    username=%s,
                    role=%s,
                    contact_number=%s,
                    employment_status=%s
                WHERE employee_id=%s
            """, (full_name, username, role, contact, status, employee_id))

        mysql.connection.commit()
        cur.close()

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/delete_employee/<int:employee_id>', methods=['DELETE'])
def delete_employee(employee_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE employees
            SET employment_status = 'inactive',
            disabled_at = NOW()
            WHERE employee_id = %s
        """, (employee_id,))

        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/admin_settings')
def admin_settings():
    if 'admin_id' in session and session.get('role') == 'admin':
        admin_id = session['admin_id']
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT full_name FROM admins WHERE admin_id = %s", (admin_id,))
        admin = cur.fetchone()
        cur.close()

        full_name = admin['full_name'] if admin else "Admin"
        return render_template('admin_setting.html', full_name=full_name)

    return redirect(url_for('login'))


@app.route('/staff_attendance')
def staff_attendance():
    if 'admin_id' in session and session.get('role') == 'admin':
        admin_id = session['admin_id']
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT full_name FROM admins WHERE admin_id = %s", (admin_id,))
        admin = cur.fetchone()
        cur.close()

        full_name = admin['full_name'] if admin else "Admin"
        return render_template('staff_attendance.html', full_name=full_name)

    return redirect(url_for('login'))


@app.route('/log_attendance', methods=['POST'])
def log_attendance():
    if 'employee_id' not in session and 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}

    action = data.get('action')          # "clock_in" or "clock_out"
    shift_type = data.get('shift_type')  # e.g. "Morning", "Afternoon", "Night"

    # ✅ Admin must choose employee_id. Cashier can use session.
    employee_id = session.get('employee_id') or data.get('employee_id')

    if not employee_id or not action or not shift_type:
        return jsonify({'success': False, 'message': 'Missing employee_id/action/shift_type'}), 400

    cur = mysql.connection.cursor(DictCursor)

    # ✅ Validate employee exists and active
    cur.execute("""
        SELECT employee_id, full_name, role, employment_status
        FROM employees
        WHERE employee_id = %s
        LIMIT 1
    """, (employee_id,))
    emp = cur.fetchone()

    if not emp:
        cur.close()
        return jsonify({'success': False, 'message': 'Employee not found'}), 404

    if emp['employment_status'] != 'active':
        cur.close()
        return jsonify({'success': False, 'message': 'Employee is inactive'}), 400

    # ✅ Get today's attendance record
    cur.execute("""
        SELECT attendance_id, clock_in, clock_out, shift_type
        FROM attendance
        WHERE employee_id = %s AND attendance_date = CURDATE()
        LIMIT 1
    """, (employee_id,))
    record = cur.fetchone()

    if action == "clock_in":
        if record:
            cur.close()
            return jsonify({'success': False, 'message': 'Already clocked in today'}), 400

        cur.execute("""
            INSERT INTO attendance (employee_id, shift_type, clock_in, attendance_date)
            VALUES (%s, %s, NOW(), CURDATE())
        """, (employee_id, shift_type))
        mysql.connection.commit()
        cur.close()

        return jsonify({
            'success': True,
            'message': 'Clock-in recorded',
            'employee': {'employee_id': emp['employee_id'], 'full_name': emp['full_name'], 'role': emp['role']},
            'action': 'clock_in',
            'shift_type': shift_type
        })

    elif action == "clock_out":
        if not record:
            cur.close()
            return jsonify({'success': False, 'message': 'No clock-in found today'}), 400

        if record['clock_out'] is not None:
            cur.close()
            return jsonify({'success': False, 'message': 'Already clocked out'}), 400

        cur.execute("""
            UPDATE attendance
            SET clock_out = NOW()
            WHERE attendance_id = %s
        """, (record['attendance_id'],))
        mysql.connection.commit()
        cur.close()

        return jsonify({
            'success': True,
            'message': 'Clock-out recorded',
            'employee': {'employee_id': emp['employee_id'], 'full_name': emp['full_name'], 'role': emp['role']},
            'action': 'clock_out',
            'shift_type': shift_type
        })

    cur.close()
    return jsonify({'success': False, 'message': 'Invalid action'}), 400

@app.route('/api/employees', methods=['GET'])
def api_employees():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("""
        SELECT employee_id, full_name, role
        FROM employees
        WHERE employment_status = 'active'
        ORDER BY full_name ASC
    """)
    rows = cur.fetchall()
    cur.close()

    return jsonify({'success': True, 'employees': rows})

@app.route('/api/attendance', methods=['GET'])
def api_attendance():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    date_str = request.args.get('date')
    search = (request.args.get('search') or "").strip()

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
    

@app.route('/clock_out_face', methods=['POST'])
def clock_out_face():
    data = request.get_json()
    employee_id = data.get('employee_id')

    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE attendance
        SET clock_out = NOW()
        WHERE employee_id = %s
        AND attendance_date = CURDATE()
        AND clock_out IS NULL
    """, (employee_id,))

    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})


# ================================ EMPLOYEE ROUTES ================================

@app.route('/cashier_dashboard')
def cashier_dashboard():
    if 'employee_id' in session and session.get('role') == 'cashier':
        employee_id = session['employee_id']

        cur = mysql.connection.cursor(DictCursor)
        cur.execute("""
            SELECT full_name, username, role, contact_number, last_login
            FROM employees
            WHERE employee_id = %s
        """, (employee_id,))
        employee = cur.fetchone()
        cur.close()

        return render_template('cashier/cashier_dashboard.html', employee=employee)

    return redirect(url_for('login'))




# ================================ LOGOUT ROUTES ================================


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)