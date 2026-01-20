from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import pyodbc
from datetime import datetime
import hashlib
import sys

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_2025'

# Database connection 
CONN_STR = (
    "DRIVER={SQL Server};"
    "SERVER=DESKTOP-6OSVBPJ;"
    "DATABASE=SecureStudentRecords;"
    "Trusted_Connection=yes;"
)

def get_db_connection():
    return pyodbc.connect(CONN_STR)

# ------------------- Authentication & Main -------------------
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return jsonify({'success': False, 'message': 'Username and password are required'})
            
            # Hash the password 
            pw_hash = hashlib.sha256(password.encode('utf-8')).digest()
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT UserID, Username, Role, ClearanceLevel, IsActive, PasswordEncrypted FROM Users WHERE Username = ?", (username,))
            user = cursor.fetchone()
            if user:
                user_id, db_username, role, clearance, is_active, stored_hash = user
                # Check if user is active
                if not is_active:
                    conn.close()
                    return jsonify({'success': False, 'message': 'Account is inactive'})
                
                # Compare password 
                password_match = False
                
                if stored_hash is not None:
                    # Convert stored_hash to bytes 
                    stored_bytes = None
                    
                    # Handle different data types 
                    try:
                        
                        if isinstance(stored_hash, bytes):
                            stored_bytes = stored_hash
                        elif isinstance(stored_hash, bytearray):
                            stored_bytes = bytes(stored_hash)
                        elif isinstance(stored_hash, memoryview):
                            stored_bytes = stored_hash.tobytes()
                        elif hasattr(stored_hash, 'tobytes'):
                    
                            stored_bytes = stored_hash.tobytes()
                        elif isinstance(stored_hash, str):
                    
                            password_match = (stored_hash.strip() == password)
                        else:
                            # Try to convert to bytes
                            try:
                                # Try using bytes
                                if hasattr(stored_hash, '__bytes__'):
                                    stored_bytes = bytes(stored_hash)
                                else:
                                    
                                    stored_bytes = bytes(stored_hash)
                            except (TypeError, ValueError, AttributeError):
                            
                                try:
                                    stored_str = str(stored_hash).strip()
                                    password_match = (stored_str == password)
                                except:
                                    pass
                        
                        # Compare hashed password if we have bytes 
                        if stored_bytes is not None and not password_match:
                        
                            if len(stored_bytes) == len(pw_hash):
                                password_match = (stored_bytes == pw_hash)
                    except Exception as e:
                        
                        try:
                            password_match = (str(stored_hash).strip() == password)
                        except:
                            pass
                
                if password_match:
                    session['user_id'] = user_id
                    session['username'] = db_username
                    session['role'] = role
                    session['clearance'] = clearance
                    conn.close()
                    return jsonify({'success': True, 'message': 'Login successful'})
                else:
                    # Debug
                    hash_type = type(stored_hash).__name__ if stored_hash is not None else 'None'
                    conn.close()
                    return jsonify({'success': False, 'message': f'Invalid password. Hash type: {hash_type}'})
            
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid username or password'})
        except Exception as e:
            if 'conn' in locals():
                conn.close()
            # Return error message for debugging
            import traceback
            error_details = traceback.format_exc()
            return jsonify({'success': False, 'message': f'Login error: {str(e)}'})
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    # Get role from session
    role = session.get('role', 'Unknown')
    return render_template('dashboard.html', username=session['username'], role=role, clearance=session['clearance'])

# ------------------- Students -------------------
@app.route('/students')
def students():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('students.html')

@app.route('/api/students', methods=['GET', 'POST'])
def api_students():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    role = session.get('role', 'Unknown')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        try:
            # Role-based access control for viewing students
            if role == 'Student':
                # Students can only see their own info
                cursor.execute("SELECT StudentID, FullName, Email, Department FROM Student WHERE StudentID = (SELECT StudentID FROM Student WHERE 1=1) LIMIT 1")
                students = []
                row = cursor.fetchone()
                if row:
                    students.append({'id': row[0], 'name': row[1], 'email': row[2], 'department': row[3]})
            elif role in ('TA', 'Instructor', 'Admin'):
                # TAs, Instructors, and Admins can see all students
                cursor.execute("SELECT StudentID, FullName, Email, Department FROM Student ORDER BY StudentID")
                students = []
                for row in cursor.fetchall():
                    students.append({'id': row[0], 'name': row[1], 'email': row[2], 'department': row[3]})
            else:
                students = []
            
            conn.close()
            return jsonify(students)
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': f'Error fetching students: {str(e)}'})
    
    else:  # POST - Add new student
        # Only Admin can add students
        if role != 'Admin':
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized - Only admins can add students'}), 403
        
        data = request.get_json()
        try:
            cursor.execute(
                "INSERT INTO Student (FullName, Email, Phone, DOB, Department) VALUES (?, ?, ?, ?, ?)",
                (data.get('fullname'), data.get('email'), data.get('phone'), data.get('dob'), data.get('department'))
            )
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Student added successfully'})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': f'Error adding student: {str(e)}'})

# ------------------- Grades -------------------
@app.route('/grades')
def grades():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('grades.html')

@app.route('/api/grades', methods=['GET', 'POST'])
def api_grades():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    role = session.get('role', 'Unknown')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        try:
            if role == 'Student':
                # Students only see their own grades
                cursor.execute("SELECT CourseName, Grade, DateEntered FROM Grade WHERE StudentID = ? ORDER BY DateEntered DESC", (session['user_id'],))
                grades = []
                for row in cursor.fetchall():
                    grades.append({
                        'course': row[0] if len(row) > 0 else 'N/A',
                        'grade': float(row[1]) if row[1] else 0,
                        'date': row[2].strftime('%Y-%m-%d') if row[2] else ''
                    })
            else:  # TA, Instructor, Admin - see all grades
                cursor.execute("SELECT GradeID, StudentID, Grade, DateEntered FROM Grade ORDER BY DateEntered DESC LIMIT 100")
                grades = []
                for row in cursor.fetchall():
                    grades.append({
                        'id': row[0],
                        'student_id': row[1],
                        'grade': float(row[2]) if row[2] else 0,
                        'date': row[3].strftime('%Y-%m-%d') if row[3] else ''
                    })
            
            conn.close()
            return jsonify(grades)
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': f'Error fetching grades: {str(e)}'})
    
    else:  # POST - Add new grade
        # Only TA, Instructor, or Admin can enter grades
        if role not in ('TA', 'Instructor', 'Admin'):
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized - Only instructors/TAs/admins can enter grades'}), 403
        
        data = request.get_json()
        try:
            cursor.execute(
                "INSERT INTO Grade (StudentID, CourseID, Grade, EnteredByUserID, DateEntered) VALUES (?, ?, ?, ?, GETDATE())",
                (data.get('student_id'), data.get('course_id'), data.get('grade'), session['user_id'])
            )
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Grade entered successfully'})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': f'Error entering grade: {str(e)}'})

# ------------------- Courses -------------------
@app.route('/courses')
def courses():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('courses.html')

@app.route('/api/courses', methods=['GET'])
def api_courses():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if session.get('clearance', 0) >= 1:
            cursor.execute("""
                SELECT CourseID, CourseName, Description, PublicInfo, InstructorID
                FROM Course
                WHERE ClassificationLevel <= ?
                ORDER BY CourseID
            """, (session['clearance'],))
        else:
            cursor.execute("""
                SELECT CourseID, CourseName, PublicInfo
                FROM Course
                WHERE ClassificationLevel = 1
                ORDER BY CourseID
            """)
        courses = []
        for row in cursor.fetchall():
            course = {'id': row[0], 'name': row[1]}
            if len(row) > 2:
                course['description'] = row[2] if row[2] else (row[3] if len(row) > 3 else '')
            if len(row) > 4:
                course['instructor_id'] = row[4]
            courses.append(course)
        conn.close()
        return jsonify(courses)
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': str(e)})

# ------------------- Attendance -------------------
@app.route('/attendance')
def attendance():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('attendance.html')

@app.route('/api/attendance', methods=['GET', 'POST'])
def api_attendance():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    role = session.get('role', 'Unknown')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        try:
            if role == 'Student':
                # Students only see their own attendance
                cursor.execute("""
                    SELECT s.FullName, c.CourseName, a.Status, a.DateRecorded
                    FROM Attendance a
                    JOIN Student s ON a.StudentID = s.StudentID
                    JOIN Course c ON a.CourseID = c.CourseID
                    WHERE s.StudentID = ? OR a.StudentID = ?
                    ORDER BY a.DateRecorded DESC
                """, (session['user_id'], session['user_id']))
                attendance = []
                for row in cursor.fetchall():
                    attendance.append({
                        'student': row[0],
                        'course': row[1],
                        'status': 'Present' if row[2] else 'Absent',
                        'date': row[3].strftime('%Y-%m-%d') if row[3] else ''
                    })
            else:  # TA, Instructor, Admin - see all
                cursor.execute("""
                    SELECT s.FullName, c.CourseName, a.Status, a.DateRecorded, u.Username
                    FROM Attendance a
                    JOIN Student s ON a.StudentID = s.StudentID
                    JOIN Course c ON a.CourseID = c.CourseID
                    LEFT JOIN Users u ON a.RecordedByUserID = u.UserID
                    ORDER BY a.DateRecorded DESC
                """)
                attendance = []
                for row in cursor.fetchall():
                    attendance.append({
                        'student': row[0],
                        'course': row[1],
                        'status': 'Present' if row[2] else 'Absent',
                        'date': row[3].strftime('%Y-%m-%d') if row[3] else '',
                        'recorded_by': row[4] if row[4] else 'N/A'
                    })
            
            conn.close()
            return jsonify(attendance)
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': f'Error fetching attendance: {str(e)}'})
    
    else:  # POST - Record attendance
        # Only TA, Instructor, or Admin can record attendance
        if role not in ('TA', 'Instructor', 'Admin'):
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized - Only instructors/TAs/admins can record attendance'}), 403
        
        data = request.get_json()
        try:
            cursor.execute(
                "INSERT INTO Attendance (StudentID, CourseID, Status, RecordedByUserID, DateRecorded) VALUES (?, ?, ?, ?, GETDATE())",
                (data.get('student_id'), data.get('course_id'), 1 if data.get('status') == 'Present' else 0, session['user_id'])
            )
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Attendance recorded successfully'})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': f'Error recording attendance: {str(e)}'})

# ------------------- Role Requests (Part B) -------------------
@app.route('/role-requests')
def role_requests_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('role_requests.html', is_admin=(session.get('role') == 'Admin'))

@app.route('/api/role-requests', methods=['GET', 'POST'])
def api_role_requests():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        try:
            if session.get('role') == 'Admin':
                cursor.execute("SELECT RequestID, Username, CurrentRole, RequestedRole, Reason, Status, RequestDate FROM RoleRequests ORDER BY RequestDate DESC")
            else:
                cursor.execute("SELECT RequestID, Username, CurrentRole, RequestedRole, Reason, Status, RequestDate FROM RoleRequests WHERE UserID = ? ORDER BY RequestDate DESC", (session['user_id'],))
            requests = []
            for row in cursor.fetchall():
                requests.append({'id': row[0], 'username': row[1], 'current_role': row[2], 'requested_role': row[3], 'reason': row[4], 'status': row[5], 'date': row[6].strftime('%Y-%m-%d %H:%M') if row[6] else ''})
            conn.close()
            return jsonify(requests)
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': str(e)})
    else:
        data = request.get_json()
        try:
            cursor.execute("INSERT INTO RoleRequests (UserID, Username, CurrentRole, RequestedRole, Reason, Comments) VALUES (?, ?, ?, ?, ?, ?)", (session['user_id'], session['username'], session['role'], data['requested_role'], data['reason'], data.get('comments', '')))
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Request submitted successfully'})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': str(e)})

@app.route('/api/role-requests/<int:request_id>/<action>', methods=['POST'])
def process_role_request(request_id, action):
    if 'username' not in session or session.get('role') != 'Admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if action == 'approve':
            cursor.execute("SELECT UserID, RequestedRole FROM RoleRequests WHERE RequestID = ?", (request_id,))
            req = cursor.fetchone()
            if req:
                user_id, new_role = req[0], req[1]
                clearance_map = {'Admin': 4, 'Instructor': 3, 'TA': 2, 'Student': 1, 'Guest': 1}
                new_clearance = clearance_map.get(new_role, 1)
                cursor.execute("UPDATE Users SET Role = ?, ClearanceLevel = ? WHERE UserID = ?", (new_role, new_clearance, user_id))
                cursor.execute("UPDATE RoleRequests SET Status = 'Approved', ProcessedDate = GETDATE(), ProcessedByAdminID = ? WHERE RequestID = ?", (session['user_id'], request_id))
        else:
            cursor.execute("UPDATE RoleRequests SET Status = 'Denied', ProcessedDate = GETDATE(), ProcessedByAdminID = ? WHERE RequestID = ?", (session['user_id'], request_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': f'Request {action}d successfully'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': str(e)})

# ------------------- Users management -------------------
@app.route('/users')
def users_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('users.html')

@app.route('/api/users', methods=['GET', 'POST'])
def api_users():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        try:
            cursor.execute("SELECT UserID, Username, Role, ClearanceLevel, IsActive, CreatedDate FROM Users ORDER BY UserID")
            users = []
            for row in cursor.fetchall():
                users.append({'id': row[0], 'username': row[1], 'role': row[2], 'clearance': row[3], 'is_active': bool(row[4]), 'created': row[5].strftime('%Y-%m-%d %H:%M') if row[5] else ''})
            conn.close()
            return jsonify(users)
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': str(e)})
    # only admin can create users
    if session.get('role') != 'Admin':
        conn.close()
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    try:
        username = data['username']
        password = data['password']
        role = data.get('role', 'Student')
        clearance = int(data.get('clearance', 1))
        pw_hash = hashlib.sha256(password.encode('utf-8')).digest()
        cursor.execute("INSERT INTO Users (Username, PasswordEncrypted, Role, ClearanceLevel) VALUES (?, ?, ?, ?)", (username, pw_hash, role, clearance))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'User created'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def api_update_user(user_id):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    if session.get('role') != 'Admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        fields = []
        params = []
        if 'role' in data:
            fields.append('Role = ?'); params.append(data['role'])
        if 'clearance' in data:
            fields.append('ClearanceLevel = ?'); params.append(int(data['clearance']))
        if 'is_active' in data:
            fields.append('IsActive = ?'); params.append(1 if data['is_active'] else 0)
        if not fields:
            conn.close()
            return jsonify({'success': False, 'message': 'No fields to update'})
        params.append(user_id)
        sql = 'UPDATE Users SET ' + ', '.join(fields) + ' WHERE UserID = ?'
        cursor.execute(sql, tuple(params))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'User updated'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': str(e)})

# ------------------- TA Assignment -------------------
@app.route('/api/ta-assign', methods=['POST', 'DELETE'])
def api_ta_assign():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    if session.get('role') not in ('Admin', 'Instructor'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    user_id = data.get('user_id'); course_id = data.get('course_id')
    if not user_id or not course_id:
        return jsonify({'success': False, 'message': 'user_id and course_id required'}), 400
    conn = get_db_connection(); cursor = conn.cursor()
    try:
        if request.method == 'POST':
            cursor.execute('INSERT INTO TAAssignment (UserID, CourseID) VALUES (?, ?)', (user_id, course_id))
            conn.commit(); conn.close(); return jsonify({'success': True, 'message': 'TA assigned to course'})
        else:
            cursor.execute('DELETE FROM TAAssignment WHERE UserID = ? AND CourseID = ?', (user_id, course_id))
            conn.commit(); conn.close(); return jsonify({'success': True, 'message': 'TA assignment removed'})
    except Exception as e:
        conn.close(); return jsonify({'success': False, 'message': str(e)})

# ------------------- Error handlers -------------------
@app.errorhandler(404)
def not_found(e):
    return redirect(url_for('login'))

@app.errorhandler(500)
def server_error(e):
    return jsonify({'success': False, 'message': 'Server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
