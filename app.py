# app.py

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_bcrypt import Bcrypt
from datetime import date, datetime
import pymysql.cursors
import pyotp
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_change_this_for_production_security'
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Configuration
DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'db': 'college_db',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}


def get_db_connection():
    return pymysql.connect(**DB_CONFIG)


# --- Context Processor to make current_year available globally ---
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}


# --- File Upload Configuration ---
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'doc', 'docx', 'pdf'}


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# --- User Management (Flask-Login Integration) ---
class User(UserMixin):
    def __init__(self, id, username, password, role, student_id=None, teacher_id=None,
                 totp_secret=None, twofa_enabled=False, first_name=None, last_name=None):  # Added first_name, last_name
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.student_id = student_id
        self.teacher_id = teacher_id
        self.totp_secret = totp_secret
        self.twofa_enabled = twofa_enabled
        self.first_name = first_name  # Store first name
        self.last_name = last_name  # Store last name

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "SELECT id, username, password, role, totp_secret, twofa_enabled FROM Users WHERE id = %s"
                cursor.execute(sql, (user_id,))
                user_data = cursor.fetchone()

                if user_data:
                    student_id = None
                    teacher_id = None
                    first_name = None
                    last_name = None

                    # Crucial: Fetch student_id or teacher_id and names based on role
                    if user_data['role'] == 'student':
                        cursor.execute("SELECT id, first_name, last_name FROM Students WHERE user_id = %s",
                                       (user_data['id'],))
                        student_data = cursor.fetchone()
                        if student_data:
                            student_id = student_data['id']
                            first_name = student_data['first_name']
                            last_name = student_data['last_name']
                    elif user_data['role'] == 'teacher':
                        cursor.execute("SELECT id, first_name, last_name FROM Teachers WHERE user_id = %s",
                                       (user_data['id'],))
                        teacher_data = cursor.fetchone()
                        if teacher_data:
                            teacher_id = teacher_data['id']
                            first_name = teacher_data['first_name']
                            last_name = teacher_data['last_name']
                    elif user_data['role'] == 'admin':
                        # For admin, use username as a fallback if no explicit name is stored
                        first_name = 'Admin'  # Default for admin
                        last_name = 'User'  # Default for admin

                    return User(user_data['id'], user_data['username'], user_data['password'],
                                user_data['role'], student_id, teacher_id,
                                user_data['totp_secret'], bool(user_data['twofa_enabled']),
                                first_name, last_name)  # Pass names to constructor
        except Exception as e:
            print(f"Error in User.get: {e}")
            return None
        finally:
            conn.close()
        return None


@login_manager.user_loader
def load_user(user_id):
    # This function is called by Flask-Login to reload the user object from the user ID stored in the session.
    # It must return a User object or None.
    return User.get(user_id)


# --- General Routes ---

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "SELECT id, username, password, role, twofa_enabled FROM Users WHERE username = %s"
                cursor.execute(sql, (username,))
                user_data = cursor.fetchone()

                if user_data and bcrypt.check_password_hash(user_data['password'], password):
                    if user_data['role'] == 'admin' and user_data['twofa_enabled']:
                        temp_secret = pyotp.random_base32()
                        ephemeral_otp_code = pyotp.TOTP(temp_secret).now()

                        session['2fa_user_id'] = user_data['id']
                        session['2fa_temp_code'] = ephemeral_otp_code
                        session['2fa_retry_count'] = 0

                        flash('Please enter the generated 2FA code.', 'info')
                        return redirect(url_for('twofa_verify'))
                    else:
                        # User.get now handles fetching student_id/teacher_id and names
                        user = User.get(user_data['id'])
                        if user:
                            login_user(user)
                            flash('Logged in successfully!', 'success')
                            return redirect(url_for('dashboard'))
                        else:
                            flash('Could not load user profile. Please try again.', 'danger')
                else:
                    flash('Invalid username or password.', 'danger')
        finally:
            conn.close()
    return render_template('login.html')


@app.route('/2fa_verify', methods=['GET', 'POST'])
def twofa_verify():
    user_id_for_2fa = session.get('2fa_user_id')
    temp_code = session.get('2fa_temp_code')
    retry_count = session.get('2fa_retry_count', 0)

    if not user_id_for_2fa or not temp_code:
        flash('Invalid 2FA request. Please log in again.', 'danger')
        return redirect(url_for('login'))

    user_to_verify = User.get(user_id_for_2fa)
    if not user_to_verify or not user_to_verify.twofa_enabled or user_to_verify.role != 'admin':
        flash('2FA not enabled or invalid user for verification.', 'danger')
        session.pop('2fa_user_id', None)
        session.pop('2fa_temp_code', None)
        session.pop('2fa_retry_count', None)
        return redirect(url_for('login'))

    MAX_RETRIES = 3
    if retry_count >= MAX_RETRIES:
        flash(f'Maximum 2FA attempts ({MAX_RETRIES}) reached. Please log in again.', 'danger')
        session.pop('2fa_user_id', None)
        session.pop('2fa_temp_code', None)
        session.pop('2fa_retry_count', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_code_entered = request.form['otp_code']

        if otp_code_entered == temp_code:
            session.pop('2fa_user_id', None)
            session.pop('2fa_temp_code', None)
            session.pop('2fa_retry_count', None)
            login_user(user_to_verify)
            flash('2FA successful! Logged in.', 'success')
            return redirect(url_for('dashboard'))
        else:
            session['2fa_retry_count'] = retry_count + 1
            remaining_attempts = MAX_RETRIES - session['2fa_retry_count']
            if remaining_attempts <= 0:
                flash(f'Invalid 2FA code. Maximum attempts reached. Please log in again.', 'danger')
                session.pop('2fa_user_id', None)
                session.pop('2fa_temp_code', None)
                session.pop('2fa_retry_count', None)
                return redirect(url_for('login'))
            else:
                flash(
                    f'Invalid 2FA code. {remaining_attempts} attempt{"s" if remaining_attempts != 1 else ""} remaining.',
                    'danger')

    return render_template('2fa_verify.html',
                           generated_code=temp_code,
                           remaining_attempts=MAX_RETRIES - retry_count)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('2fa_user_id', None)
    session.pop('2fa_temp_code', None)
    session.pop('2fa_retry_count', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    elif current_user.role == 'student':
        return redirect(url_for('student_dashboard'))
    return "Welcome to your dashboard!"


# --- Admin Routes ---

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. You do not have administrative privileges.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('admin/dashboard.html')


@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT
                u.id, u.username, u.email, u.role, u.twofa_enabled,
                s.first_name AS student_first_name, s.last_name AS student_last_name, p.name AS program_name,
                t.first_name AS teacher_first_name, t.last_name AS teacher_last_name
            FROM Users u
            LEFT JOIN Students s ON u.id = s.user_id
            LEFT JOIN Teachers t ON u.id = t.user_id
            LEFT JOIN Programs p ON s.program_id = p.id
            ORDER BY u.role, u.username
            """
            cursor.execute(sql)
            users = cursor.fetchall()
    finally:
        conn.close()
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def admin_add_user():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    program_categories = []
    programs = []  # Will initially be empty or contain all for non-JS fallback
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM ProgramCategories ORDER BY name")
            program_categories = cursor.fetchall()
            # Initially fetch all programs for fallback or if JS is disabled
            cursor.execute("SELECT id, name, category_id FROM Programs ORDER BY name")
            programs = cursor.fetchall()
    finally:
        conn.close()

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        program_id = request.form.get('program_id')  # This will be the selected program ID
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                conn.begin()

                sql_user = "INSERT INTO Users (username, email, password, role) VALUES (%s, %s, %s, %s)"
                cursor.execute(sql_user, (username, email, hashed_password, role))
                user_id = cursor.lastrowid

                if role == 'student':
                    # Ensure program_id is passed only if it's a student
                    sql_student = "INSERT INTO Students (user_id, program_id, first_name, last_name, enrollment_date) VALUES (%s, %s, %s, %s, %s)"
                    cursor.execute(sql_student,
                                   (user_id, program_id if program_id else None, first_name, last_name, date.today()))
                elif role == 'teacher':
                    sql_teacher = "INSERT INTO Teachers (user_id, first_name, last_name, hire_date) VALUES (%s, %s, %s, %s)"
                    cursor.execute(sql_teacher, (user_id, first_name, last_name, date.today()))

                conn.commit()
                flash(f'{role.capitalize()} {username} added successfully!', 'success')
                return redirect(url_for('admin_users'))

        except pymysql.err.IntegrityError as e:
            conn.rollback()
            flash(f'Error adding user: {e}. Username or Email might already exist.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('admin/add_user.html', program_categories=program_categories, programs=programs)


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    user = None
    student_details = None
    teacher_details = None
    program_categories = []
    programs = []  # Will initially be empty or contain all for non-JS fallback

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username, email, role, twofa_enabled FROM Users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

            if not user:
                flash('User not found.', 'danger')
                return redirect(url_for('admin_users'))

            if user['role'] == 'student':
                cursor.execute("SELECT id, first_name, last_name, program_id FROM Students WHERE user_id = %s",
                               (user_id,))
                student_details = cursor.fetchone()
            elif user['role'] == 'teacher':
                cursor.execute("SELECT id, first_name, last_name FROM Teachers WHERE user_id = %s", (user_id,))
                teacher_details = cursor.fetchone()

            cursor.execute("SELECT id, name FROM ProgramCategories ORDER BY name")
            program_categories = cursor.fetchall()
            cursor.execute("SELECT id, name, category_id FROM Programs ORDER BY name")
            programs = cursor.fetchall()  # All programs for initial load/fallback

    finally:
        conn.close()

    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']
        new_role = request.form['role']
        new_password = request.form.get('password')
        new_first_name = request.form.get('first_name')
        new_last_name = request.form.get('last_name')
        new_program_id = request.form.get('program_id')  # This will be the selected program ID
        new_twofa_enabled = request.form.get('twofa_enabled') == 'on'

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                conn.begin()

                sql_update_user = "UPDATE Users SET username = %s, email = %s, role = %s, twofa_enabled = %s WHERE id = %s"
                params_update_user = [new_username, new_email, new_role, new_twofa_enabled, user_id]
                if new_password:
                    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    sql_update_user = "UPDATE Users SET username = %s, email = %s, password = %s, role = %s, twofa_enabled = %s WHERE id = %s"
                    params_update_user.insert(2, hashed_password)

                cursor.execute(sql_update_user, tuple(params_update_user))

                if user['role'] != new_role:
                    if user['role'] == 'student':
                        cursor.execute("DELETE FROM Students WHERE user_id = %s", (user_id,))
                    elif user['role'] == 'teacher':
                        cursor.execute("DELETE FROM Teachers WHERE user_id = %s", (user_id,))

                    if new_role == 'student':
                        sql_insert_student = "INSERT INTO Students (user_id, program_id, first_name, last_name, enrollment_date) VALUES (%s, %s, %s, %s, %s)"
                        cursor.execute(sql_insert_student,
                                       (user_id, new_program_id if new_program_id else None, new_first_name,
                                        new_last_name, date.today()))
                    elif new_role == 'teacher':
                        sql_insert_teacher = "INSERT INTO Teachers (user_id, first_name, last_name, hire_date) VALUES (%s, %s, %s, %s)"
                        cursor.execute(sql_teacher, (user_id, new_first_name, new_last_name, date.today()))
                else:
                    if new_role == 'student':
                        sql_update_student = "UPDATE Students SET first_name = %s, last_name = %s, program_id = %s WHERE user_id = %s"
                        cursor.execute(sql_update_student,
                                       (new_first_name, new_last_name, new_program_id if new_program_id else None,
                                        user_id))
                    elif new_role == 'teacher':
                        sql_update_teacher = "UPDATE Teachers SET first_name = %s, last_name = %s WHERE user_id = %s"
                        cursor.execute(sql_update_teacher, (new_first_name, new_last_name, user_id))

                conn.commit()
                flash(f'User {new_username} updated successfully!', 'success')
                return redirect(url_for('admin_users'))

        except pymysql.err.IntegrityError as e:
            conn.rollback()
            flash(f'Error updating user: {e}. Username or Email might already exist.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()

    return render_template('admin/edit_user.html', user=user, student_details=student_details,
                           teacher_details=teacher_details, program_categories=program_categories, programs=programs)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "DELETE FROM Users WHERE id = %s"
            cursor.execute(sql, (user_id,))
            conn.commit()
            flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_users'))


# --- Admin: Program Categories Management (NEW) ---
@app.route('/admin/program_categories')
@login_required
def admin_program_categories():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM ProgramCategories ORDER BY name")
            categories = cursor.fetchall()
    finally:
        conn.close()
    return render_template('admin/program_categories.html', categories=categories)


@app.route('/admin/program_categories/add', methods=['GET', 'POST'])
@login_required
def admin_add_program_category():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form['name']
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "INSERT INTO ProgramCategories (name) VALUES (%s)"
                cursor.execute(sql, (name,))
                conn.commit()
                flash(f'Program category "{name}" added successfully!', 'success')
                return redirect(url_for('admin_program_categories'))
        except pymysql.err.IntegrityError as e:
            flash(f'Error adding category: {e}. Category name might already exist.', 'danger')
        finally:
            conn.close()
    return render_template('admin/add_program_category.html')


@app.route('/admin/program_categories/edit/<int:category_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_program_category(category_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    category = None
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM ProgramCategories WHERE id = %s", (category_id,))
            category = cursor.fetchone()
            if not category:
                flash('Program category not found.', 'danger')
                return redirect(url_for('admin_program_categories'))
    finally:
        conn.close()

    if request.method == 'POST':
        new_name = request.form['name']
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "UPDATE ProgramCategories SET name = %s WHERE id = %s"
                cursor.execute(sql, (new_name, category_id))
                conn.commit()
                flash(f'Program category "{new_name}" updated successfully!', 'success')
                return redirect(url_for('admin_program_categories'))
        except pymysql.err.IntegrityError as e:
            flash(f'Error updating category: {e}. Category name might already exist.', 'danger')
        finally:
            conn.close()
    return render_template('admin/edit_program_category.html', category=category)


@app.route('/admin/program_categories/delete/<int:category_id>', methods=['POST'])
@login_required
def admin_delete_program_category(category_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            conn.begin()
            # Set category_id to NULL for programs belonging to this category
            cursor.execute("UPDATE Programs SET category_id = NULL WHERE category_id = %s", (category_id,))
            sql = "DELETE FROM ProgramCategories WHERE id = %s"
            cursor.execute(sql, (category_id,))
            conn.commit()
            flash('Program category deleted successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting program category: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_program_categories'))


# --- API Endpoint for Programs by Category ---
@app.route('/api/programs_by_category/<int:category_id>')
@login_required
def api_programs_by_category(category_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db_connection()
    programs = []
    try:
        with conn.cursor() as cursor:
            if category_id == 0:  # Special ID for "No Category" or "All Programs"
                cursor.execute("SELECT id, name FROM Programs ORDER BY name")
            else:
                cursor.execute("SELECT id, name FROM Programs WHERE category_id = %s ORDER BY name", (category_id,))
            programs = cursor.fetchall()
    finally:
        conn.close()
    return jsonify(programs)


# --- Admin: Program Management ---
@app.route('/admin/programs')
@login_required
def admin_programs():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT p.id, p.name, p.description, pc.name AS category_name
            FROM Programs p
            LEFT JOIN ProgramCategories pc ON p.category_id = pc.id
            ORDER BY p.name
            """
            cursor.execute(sql)
            programs = cursor.fetchall()
    finally:
        conn.close()
    return render_template('admin/programs.html', programs=programs)


@app.route('/admin/programs/add', methods=['GET', 'POST'])
@login_required
def admin_add_program():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    program_categories = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM ProgramCategories ORDER BY name")
            program_categories = cursor.fetchall()
    finally:
        conn.close()

    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description')
        category_id = request.form.get('category_id')  # New: Category ID for the program

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "INSERT INTO Programs (name, description, category_id) VALUES (%s, %s, %s)"
                cursor.execute(sql, (name, description, category_id if category_id else None))
                conn.commit()
                flash(f'Program "{name}" added successfully!', 'success')
                return redirect(url_for('admin_programs'))
        except pymysql.err.IntegrityError as e:
            flash(f'Error adding program: {e}. Program name might already exist.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('admin/add_program.html', program_categories=program_categories)


@app.route('/admin/programs/edit/<int:program_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_program(program_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    program = None
    program_categories = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, description, category_id FROM Programs WHERE id = %s", (program_id,))
            program = cursor.fetchone()
            if not program:
                flash('Program not found.', 'danger')
                return redirect(url_for('admin_programs'))

            cursor.execute("SELECT id, name FROM ProgramCategories ORDER BY name")
            program_categories = cursor.fetchall()
    finally:
        conn.close()

    if request.method == 'POST':
        new_name = request.form['name']
        new_description = request.form.get('description')
        new_category_id = request.form.get('category_id')

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "UPDATE Programs SET name = %s, description = %s, category_id = %s WHERE id = %s"
                cursor.execute(sql,
                               (new_name, new_description, new_category_id if new_category_id else None, program_id))
                conn.commit()
                flash(f'Program "{new_name}" updated successfully!', 'success')
                return redirect(url_for('admin_programs'))
        except pymysql.err.IntegrityError as e:
            flash(f'Error updating program: {e}. Program name might already exist.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('admin/edit_program.html', program=program, program_categories=program_categories)


@app.route('/admin/programs/delete/<int:program_id>', methods=['POST'])
@login_required
def admin_delete_program(program_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            conn.begin()

            cursor.execute("UPDATE Students SET program_id = NULL WHERE program_id = %s", (program_id,))
            # Also set course_id to NULL for courses belonging to this program
            cursor.execute("UPDATE Courses SET program_id = NULL WHERE program_id = %s", (program_id,))

            sql = "DELETE FROM Programs WHERE id = %s"
            cursor.execute(sql, (program_id,))
            conn.commit()
            flash('Program deleted successfully and associated students/courses updated!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting program: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_programs'))


# --- Admin: Course Management ---
@app.route('/admin/courses')
@login_required
def admin_courses():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    # This will hold programs, and each program will have a list of its courses
    programs_with_courses = []
    try:
        with conn.cursor() as cursor:
            # Fetch all programs
            cursor.execute("SELECT id, name FROM Programs ORDER BY name")
            programs = cursor.fetchall()

            for program in programs:
                # For each program, fetch its courses
                sql_courses = """
                SELECT c.id, c.name, c.code, c.description,
                       t.first_name AS teacher_first_name, t.last_name AS teacher_last_name
                FROM Courses c
                LEFT JOIN Teachers t ON c.teacher_id = t.id
                WHERE c.program_id = %s
                ORDER BY c.name
                """
                cursor.execute(sql_courses, (program['id'],))
                program_courses = cursor.fetchall()
                program['courses'] = program_courses  # Add courses list to the program dictionary
                programs_with_courses.append(program)

            # Handle courses not assigned to any program
            sql_unassigned_courses = """
            SELECT c.id, c.name, c.code, c.description,
                   t.first_name AS teacher_first_name, t.last_name AS teacher_last_name
            FROM Courses c
            LEFT JOIN Teachers t ON c.teacher_id = t.id
            WHERE c.program_id IS NULL
            ORDER BY c.name
            """
            cursor.execute(sql_unassigned_courses)
            unassigned_courses = cursor.fetchall()
            if unassigned_courses:
                programs_with_courses.append({
                    'id': None,  # Indicate no program
                    'name': 'Unassigned Courses',
                    'courses': unassigned_courses
                })

    finally:
        conn.close()
    return render_template('admin/courses.html', programs_with_courses=programs_with_courses)


@app.route('/admin/courses/add', methods=['GET', 'POST'])
@login_required
def admin_add_course():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    programs = []
    teachers = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM Programs ORDER BY name")
            programs = cursor.fetchall()
            cursor.execute("SELECT id, first_name, last_name FROM Teachers ORDER BY first_name")
            teachers = cursor.fetchall()
    finally:
        conn.close()

    if request.method == 'POST':
        name = request.form['name']
        code = request.form['code']
        description = request.form.get('description')  # Get description
        program_id = request.form.get('program_id')
        teacher_id = request.form.get('teacher_id')  # This is for the course coordinator

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "INSERT INTO Courses (name, code, description, program_id, teacher_id) VALUES (%s, %s, %s, %s, %s)"
                cursor.execute(sql, (name, code, description, program_id if program_id else None,
                                     teacher_id if teacher_id else None))
                conn.commit()
                flash(f'Course "{name}" added successfully!', 'success')
                return redirect(url_for('admin_courses'))
        except pymysql.err.IntegrityError as e:
            flash(f'Error adding course: {e}. Course code might already exist.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('admin/add_course.html', programs=programs, teachers=teachers)


@app.route('/admin/courses/edit/<int:course_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_course(course_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    course = None
    programs = []
    teachers = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, code, description, program_id, teacher_id FROM Courses WHERE id = %s",
                           (course_id,))
            course = cursor.fetchone()
            if not course:
                flash('Course not found.', 'danger')
                return redirect(url_for('admin_courses'))

            cursor.execute("SELECT id, name FROM Programs ORDER BY name")
            programs = cursor.fetchall()
            cursor.execute("SELECT id, first_name, last_name FROM Teachers ORDER BY first_name")
            teachers = cursor.fetchall()
    finally:
        conn.close()

    if request.method == 'POST':
        new_name = request.form['name']
        new_code = request.form['code']
        new_description = request.form.get('description')  # Get new description
        new_program_id = request.form.get('program_id')
        new_teacher_id = request.form.get('teacher_id')  # This is for the course coordinator

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "UPDATE Courses SET name = %s, code = %s, description = %s, program_id = %s, teacher_id = %s WHERE id = %s"
                cursor.execute(sql, (new_name, new_code, new_description, new_program_id if new_program_id else None,
                                     new_teacher_id if new_teacher_id else None, course_id))
                conn.commit()
                flash(f'Course "{new_name}" updated successfully!', 'success')
                return redirect(url_for('admin_courses'))
        except pymysql.err.IntegrityError as e:
            flash(f'Error updating course: {e}. Course code might already exist.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('admin/edit_course.html', course=course, programs=programs, teachers=teachers)


@app.route('/admin/courses/delete/<int:course_id>', methods=['POST'])
@login_required
def admin_delete_course(course_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # No need for sql_check_owner here, as admin can delete any course
            sql = "DELETE FROM Courses WHERE id = %s"
            cursor.execute(sql, (course_id,))
            conn.commit()
            flash('Course deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting course: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_courses'))


# --- Admin: Course Unit Management (NEW) ---
@app.route('/admin/courses/<int:course_id>/units')
@login_required
def admin_course_units(course_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    course_info = None
    course_units = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, code FROM Courses WHERE id = %s", (course_id,))
            course_info = cursor.fetchone()
            if not course_info:
                flash('Course not found.', 'danger')
                return redirect(url_for('admin_courses'))

            # Fetch units along with their assigned teacher's name
            sql_units = """
            SELECT cu.id, cu.unit_code, cu.unit_title, cu.credit_points, cu.prerequisites, cu.semester,
                   t.first_name AS teacher_first_name, t.last_name AS teacher_last_name
            FROM CourseUnits cu
            LEFT JOIN Teachers t ON cu.teacher_id = t.id
            WHERE cu.course_id = %s
            ORDER BY cu.semester, cu.unit_code
            """
            cursor.execute(sql_units, (course_id,))
            course_units = cursor.fetchall()
    finally:
        conn.close()
    return render_template('admin/course_units.html', course_info=course_info, course_units=course_units)


@app.route('/admin/courses/<int:course_id>/units/add', methods=['GET', 'POST'])
@login_required
def admin_add_course_unit(course_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    course_info = None
    teachers = []  # Fetch all teachers for the dropdown
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, code FROM Courses WHERE id = %s", (course_id,))
            course_info = cursor.fetchone()
            if not course_info:
                flash('Course not found.', 'danger')
                return redirect(url_for('admin_courses'))

            cursor.execute("SELECT id, first_name, last_name FROM Teachers ORDER BY first_name, last_name")
            teachers = cursor.fetchall()
    finally:
        conn.close()

    if request.method == 'POST':
        unit_code = request.form['unit_code']
        unit_title = request.form['unit_title']
        credit_points = request.form['credit_points']
        prerequisites = request.form.get('prerequisites')
        semester = request.form['semester']
        unit_teacher_id = request.form.get('unit_teacher_id')  # New: Teacher assigned to unit

        if not unit_code or not unit_title or not credit_points or not semester:
            flash('All required fields must be filled.', 'danger')
            return render_template('admin/add_course_unit.html', course_info=course_info, teachers=teachers)

        try:
            credit_points = int(credit_points)
            if credit_points <= 0:
                raise ValueError("Credit points must be a positive number.")
        except ValueError as e:
            flash(f'Invalid input for credit points: {e}', 'danger')
            return render_template('admin/add_course_unit.html', course_info=course_info, teachers=teachers)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "INSERT INTO CourseUnits (course_id, unit_code, unit_title, credit_points, prerequisites, semester, teacher_id) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                cursor.execute(sql, (course_id, unit_code, unit_title, credit_points, prerequisites, semester,
                                     unit_teacher_id if unit_teacher_id else None))
                conn.commit()
                flash(f'Unit "{unit_title}" added successfully to {course_info["name"]}!', 'success')
                return redirect(url_for('admin_course_units', course_id=course_id))
        except pymysql.err.IntegrityError as e:
            flash(f'Error adding unit: {e}. Unit code might already exist for this course.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('admin/add_course_unit.html', course_info=course_info, teachers=teachers)


@app.route('/admin/courses/<int:course_id>/units/edit/<int:unit_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_course_unit(course_id, unit_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    course_info = None
    unit_info = None
    teachers = []  # Fetch all teachers for the dropdown
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, code FROM Courses WHERE id = %s", (course_id,))
            course_info = cursor.fetchone()
            if not course_info:
                flash('Course not found.', 'danger')
                return redirect(url_for('admin_courses'))

            cursor.execute(
                "SELECT id, unit_code, unit_title, credit_points, prerequisites, semester, teacher_id FROM CourseUnits WHERE id = %s AND course_id = %s",
                (unit_id, course_id))
            unit_info = cursor.fetchone()
            if not unit_info:
                flash('Course unit not found or does not belong to this course.', 'danger')
                return redirect(url_for('admin_course_units', course_id=course_id))

            cursor.execute("SELECT id, first_name, last_name FROM Teachers ORDER BY first_name, last_name")
            teachers = cursor.fetchall()
    finally:
        conn.close()

    if request.method == 'POST':
        new_unit_code = request.form['unit_code']
        new_unit_title = request.form['unit_title']
        new_credit_points = request.form['credit_points']
        new_prerequisites = request.form.get('prerequisites')
        new_semester = request.form['semester']
        new_unit_teacher_id = request.form.get('unit_teacher_id')  # New: Teacher assigned to unit

        if not new_unit_code or not new_unit_title or not new_credit_points or not new_semester:
            flash('All required fields must be filled.', 'danger')
            return render_template('admin/edit_course_unit.html', course_info=course_info, unit_info=unit_info,
                                   teachers=teachers)

        try:
            new_credit_points = int(new_credit_points)
            if new_credit_points <= 0:
                raise ValueError("Credit points must be a positive number.")
        except ValueError as e:
            flash(f'Invalid input for credit points: {e}', 'danger')
            return render_template('admin/edit_course_unit.html', course_info=course_info, unit_info=unit_info,
                                   teachers=teachers)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "UPDATE CourseUnits SET unit_code = %s, unit_title = %s, credit_points = %s, prerequisites = %s, semester = %s, teacher_id = %s WHERE id = %s AND course_id = %s"
                cursor.execute(sql, (new_unit_code, new_unit_title, new_credit_points, new_prerequisites, new_semester,
                                     new_unit_teacher_id if new_unit_teacher_id else None, unit_id, course_id))
                conn.commit()
                flash(f'Unit "{new_unit_title}" updated successfully!', 'success')
                return redirect(url_for('admin_course_units', course_id=course_id))
        except pymysql.err.IntegrityError as e:
            flash(f'Error updating unit: {e}. Unit code might already exist for this course.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('admin/edit_course_unit.html', course_info=course_info, unit_info=unit_info,
                           teachers=teachers)


@app.route('/admin/courses/delete/<int:unit_id>', methods=['POST'])
@login_required
def admin_delete_course_unit(course_id, unit_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Verify the unit belongs to the specified course
            cursor.execute("SELECT id FROM CourseUnits WHERE id = %s AND course_id = %s", (unit_id, course_id))
            if not cursor.fetchone():
                flash('Course unit not found or does not belong to this course.', 'danger')
                return redirect(url_for('admin_course_units', course_id=course_id))

            sql = "DELETE FROM CourseUnits WHERE id = %s"
            cursor.execute(sql, (unit_id,))
            conn.commit()
            flash('Course unit deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting course unit: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_course_units', course_id=course_id))


# --- Admin: Student Course Enrollment Management (NEW) ---
@app.route('/admin/courses/<int:course_id>/enrollments', methods=['GET', 'POST'])
@login_required
def admin_course_enrollments(course_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    course_info = None
    enrolled_students = []
    available_students = []  # Students not yet enrolled in this course

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, code FROM Courses WHERE id = %s", (course_id,))
            course_info = cursor.fetchone()
            if not course_info:
                flash('Course not found.', 'danger')
                return redirect(url_for('admin_courses'))

            # Fetch currently enrolled students
            sql_enrolled = """
            SELECT
                s.id AS student_id, s.first_name, s.last_name, u.username,
                sce.enrollment_date, sce.status AS enrollment_status, sce.id AS enrollment_record_id
            FROM StudentCourseEnrollments sce
            JOIN Students s ON sce.student_id = s.id
            JOIN Users u ON s.user_id = u.id
            WHERE sce.course_id = %s
            ORDER BY s.last_name, s.first_name
            """
            cursor.execute(sql_enrolled, (course_id,))
            enrolled_students = cursor.fetchall()

            # Fetch students NOT yet enrolled in this course
            sql_available = """
            SELECT s.id, s.first_name, s.last_name, u.username
            FROM Students s
            JOIN Users u ON s.user_id = u.id
            WHERE s.id NOT IN (
                SELECT student_id FROM StudentCourseEnrollments WHERE course_id = %s
            )
            ORDER BY s.last_name, s.first_name
            """
            cursor.execute(sql_available, (course_id,))
            available_students = cursor.fetchall()

    finally:
        conn.close()

    return render_template('admin/course_enrollments.html',
                           course_info=course_info,
                           enrolled_students=enrolled_students,
                           available_students=available_students)


@app.route('/admin/courses/<int:course_id>/enroll_student', methods=['POST'])
@login_required
def admin_enroll_student(course_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    student_id = request.form.get('student_id')
    if not student_id:
        flash('No student selected for enrollment.', 'danger')
        return redirect(url_for('admin_course_enrollments', course_id=course_id))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if student is already enrolled
            cursor.execute("SELECT id FROM StudentCourseEnrollments WHERE student_id = %s AND course_id = %s",
                           (student_id, course_id))
            if cursor.fetchone():
                flash('Student is already enrolled in this course.', 'info')
            else:
                sql = "INSERT INTO StudentCourseEnrollments (student_id, course_id, enrollment_date, status) VALUES (%s, %s, %s, 'Enrolled')"
                cursor.execute(sql, (student_id, course_id, datetime.now()))
                conn.commit()
                flash('Student enrolled successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error enrolling student: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_course_enrollments', course_id=course_id))


@app.route('/admin/courses/<int:course_id>/unenroll_student/<int:enrollment_record_id>', methods=['POST'])
@login_required
def admin_unenroll_student(course_id, enrollment_record_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Verify the enrollment record belongs to this course
            cursor.execute("SELECT id FROM StudentCourseEnrollments WHERE id = %s AND course_id = %s",
                           (enrollment_record_id, course_id))
            if not cursor.fetchone():
                flash('Enrollment record not found or does not belong to this course.', 'danger')
                return redirect(url_for('admin_course_enrollments', course_id=course_id))

            sql = "DELETE FROM StudentCourseEnrollments WHERE id = %s"
            cursor.execute(sql, (enrollment_record_id,))
            conn.commit()
            flash('Student unenrolled successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error unenrolling student: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_course_enrollments', course_id=course_id))


# --- Public Course Catalog Route ---
@app.route('/courses_catalog')
def courses_catalog():
    """Publicly accessible course catalog, grouped by program type."""
    conn = get_db_connection()
    programs_with_courses = []
    try:
        with conn.cursor() as cursor:
            # Fetch all programs
            cursor.execute("SELECT id, name FROM Programs ORDER BY name")
            programs = cursor.fetchall()

            for program in programs:
                # For each program, fetch its courses
                sql_courses = """
                SELECT c.id, c.name, c.code, c.description,
                       t.first_name AS teacher_first_name, t.last_name AS teacher_last_name
                FROM Courses c
                LEFT JOIN Teachers t ON c.teacher_id = t.id
                WHERE c.program_id = %s
                ORDER BY c.name
                """
                cursor.execute(sql_courses, (program['id'],))
                program_courses = cursor.fetchall()
                program['courses'] = program_courses  # Add courses list to the program dictionary
                programs_with_courses.append(program)

            # Handle courses not assigned to any program (optional, but good for completeness)
            sql_unassigned_courses = """
            SELECT c.id, c.name, c.code, c.description,
                   t.first_name AS teacher_first_name, t.last_name AS teacher_last_name
            FROM Courses c
            LEFT JOIN Teachers t ON c.teacher_id = t.id
            WHERE c.program_id IS NULL
            ORDER BY c.name
            """
            cursor.execute(sql_unassigned_courses)
            unassigned_courses = cursor.fetchall()
            if unassigned_courses:
                programs_with_courses.append({
                    'id': None,  # Indicate no program
                    'name': 'Other Courses',  # Or 'Unassigned Courses'
                    'courses': unassigned_courses
                })

    finally:
        conn.close()
    return render_template('public/courses_catalog.html', programs_with_courses=programs_with_courses)


# --- Teacher Routes ---
@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        flash('Access denied. You do not have teacher privileges.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    assigned_courses = []
    pending_submissions_count = 0
    graded_assessments_count = 0
    new_feedback_count = 0
    total_students_in_courses = 0
    try:
        with conn.cursor() as cursor:
            # Get the teacher's ID from the Teachers table
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            # Assigned Courses: Get courses where the teacher is assigned to at least one unit
            sql_assigned_courses = """
            SELECT DISTINCT c.id, c.name, c.code, p.name AS program_name
            FROM Courses c
            JOIN CourseUnits cu ON c.id = cu.course_id
            LEFT JOIN Programs p ON c.program_id = p.id
            WHERE cu.teacher_id = %s
            ORDER BY c.name
            """
            cursor.execute(sql_assigned_courses, (teacher_db_id,))
            assigned_courses = cursor.fetchall()

            # Pending Submissions Count
            sql_pending_count = """
            SELECT COUNT(g.id)
            FROM Grades g
            JOIN Assessments a ON g.assessment_id = a.id
            JOIN CourseUnits cu ON a.course_unit_id = cu.id
            WHERE cu.teacher_id = %s AND g.status = 'Submitted' AND g.grade IS NULL
            """
            cursor.execute(sql_pending_count, (teacher_db_id,))
            pending_submissions_count = cursor.fetchone()['COUNT(g.id)']

            # Graded Assessments Count
            sql_graded_count = """
            SELECT COUNT(g.id)
            FROM Grades g
            JOIN Assessments a ON g.assessment_id = a.id
            JOIN CourseUnits cu ON a.course_unit_id = cu.id
            WHERE cu.teacher_id = %s AND g.status = 'Graded' AND g.grade IS NOT NULL
            """
            cursor.execute(sql_graded_count, (teacher_db_id,))
            graded_assessments_count = cursor.fetchone()['COUNT(g.id)']

            # New Feedback Count
            sql_new_feedback_count = """
            SELECT COUNT(sf.id)
            FROM StudentFeedback sf
            WHERE sf.teacher_id = %s AND sf.status = 'New'
            """
            cursor.execute(sql_new_feedback_count, (teacher_db_id,))
            new_feedback_count = cursor.fetchone()['COUNT(sf.id)']

            # Total Students in courses where this teacher teaches at least one unit
            sql_total_students = """
            SELECT COUNT(DISTINCT sce.student_id)
            FROM StudentCourseEnrollments sce
            JOIN CourseUnits cu ON sce.course_id = cu.course_id
            WHERE cu.teacher_id = %s AND sce.status = 'Enrolled'
            """
            cursor.execute(sql_total_students, (teacher_db_id,))
            total_students_in_courses = cursor.fetchone()['COUNT(DISTINCT sce.student_id)']

    finally:
        conn.close()

    return render_template('teacher/dashboard.html',
                           assigned_courses=assigned_courses,
                           pending_submissions_count=pending_submissions_count,
                           graded_assessments_count=graded_assessments_count,
                           new_feedback_count=new_feedback_count,
                           total_students_in_courses=total_students_in_courses)


@app.route('/teacher/assessments')
@login_required
def teacher_assessments():
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    assessments = []
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            # Fetch assessments for units assigned to this teacher
            sql = """
            SELECT a.id, a.title, a.description, a.due_date, a.max_points,
                   c.name AS course_name, c.code AS course_code,
                   cu.unit_code, cu.unit_title
            FROM Assessments a
            JOIN CourseUnits cu ON a.course_unit_id = cu.id
            JOIN Courses c ON cu.course_id = c.id
            WHERE cu.teacher_id = %s
            ORDER BY a.due_date DESC, c.name, cu.unit_title, a.title
            """
            cursor.execute(sql, (teacher_db_id,))
            assessments = cursor.fetchall()
    finally:
        conn.close()
    return render_template('teacher/assessments.html', assessments=assessments)


@app.route('/teacher/assessments/add', methods=['GET', 'POST'])
@login_required
def teacher_add_assessment():
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    teacher_courses = []
    course_units_by_course = {}
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            # Get courses where the teacher teaches at least one unit
            cursor.execute("""
                SELECT DISTINCT c.id, c.name, c.code
                FROM Courses c
                JOIN CourseUnits cu ON c.id = cu.course_id
                WHERE cu.teacher_id = %s
                ORDER BY c.name
            """, (teacher_db_id,))
            teacher_courses = cursor.fetchall()

            # Get all units taught by this teacher, grouped by course
            cursor.execute("""
                SELECT cu.id AS unit_id, cu.unit_code, cu.unit_title, cu.course_id
                FROM CourseUnits cu
                WHERE cu.teacher_id = %s
                ORDER BY cu.course_id, cu.unit_code
            """, (teacher_db_id,))
            all_teacher_units = cursor.fetchall()

            for unit in all_teacher_units:
                if unit['course_id'] not in course_units_by_course:
                    course_units_by_course[unit['course_id']] = []
                course_units_by_course[unit['course_id']].append(unit)

    finally:
        conn.close()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description')
        course_unit_id = request.form['course_unit_id']
        due_date_str = request.form['due_date']
        max_points = request.form['max_points']

        if not title or not course_unit_id or not due_date_str or not max_points:
            flash('All required fields must be filled.', 'danger')
            return render_template('teacher/add_assessment.html', teacher_courses=teacher_courses,
                                   course_units_by_course=course_units_by_course)

        try:
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
            max_points = int(max_points)
            if max_points <= 0:
                raise ValueError("Max points must be a positive number.")
        except ValueError as e:
            flash(f'Invalid input: {e}', 'danger')
            return render_template('teacher/add_assessment.html', teacher_courses=teacher_courses,
                                   course_units_by_course=course_units_by_course)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                teacher_db_id = current_user.teacher_id
                if not teacher_db_id:
                    flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                    return redirect(url_for('dashboard'))

                # Verify that the selected course unit is assigned to this teacher
                cursor.execute("""
                    SELECT id FROM CourseUnits
                    WHERE id = %s AND teacher_id = %s
                """, (course_unit_id, teacher_db_id))
                if not cursor.fetchone():
                    flash('Invalid unit selection. You are not assigned to this unit.', 'danger')
                    return render_template('teacher/add_assessment.html', teacher_courses=teacher_courses,
                                           course_units_by_course=course_units_by_course)

                # Fetch the parent course_id from the selected course_unit_id
                cursor.execute("SELECT course_id FROM CourseUnits WHERE id = %s", (course_unit_id,))
                parent_course_id = cursor.fetchone()['course_id']

                # Insert assessment linked to course_unit_id and its parent course_id
                sql = "INSERT INTO Assessments (title, description, course_id, course_unit_id, due_date, max_points) VALUES (%s, %s, %s, %s, %s, %s)"
                cursor.execute(sql, (title, description, parent_course_id, course_unit_id, due_date, max_points))
                conn.commit()
                flash(f'Assessment "{title}" added successfully!', 'success')
                return redirect(url_for('teacher_assessments'))
        except pymysql.err.IntegrityError as e:
            flash(f'Error adding assessment: {e}.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('teacher/add_assessment.html', teacher_courses=teacher_courses,
                           course_units_by_course=course_units_by_course)


@app.route('/teacher/assessments/edit/<int:assessment_id>', methods=['GET', 'POST'])
@login_required
def teacher_edit_assessment(assessment_id):
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    assessment = None
    teacher_courses = []
    course_units_by_course = {}
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            # Fetch assessment details, including its linked course_unit_id
            sql_assessment = """
            SELECT a.id, a.title, a.description, a.due_date, a.max_points, a.course_id, a.course_unit_id
            FROM Assessments a
            JOIN CourseUnits cu ON a.course_unit_id = cu.id
            WHERE a.id = %s AND cu.teacher_id = %s
            """
            cursor.execute(sql_assessment, (assessment_id, teacher_db_id))
            assessment = cursor.fetchone()
            if not assessment:
                flash('Assessment not found or you do not have permission to edit it.', 'danger')
                return redirect(url_for('teacher_assessments'))

            # Get courses where the teacher teaches at least one unit
            cursor.execute("""
                SELECT DISTINCT c.id, c.name, c.code
                FROM Courses c
                JOIN CourseUnits cu ON c.id = cu.course_id
                WHERE cu.teacher_id = %s
                ORDER BY c.name
            """, (teacher_db_id,))
            teacher_courses = cursor.fetchall()

            # Get all units taught by this teacher, grouped by course
            cursor.execute("""
                SELECT cu.id AS unit_id, cu.unit_code, cu.unit_title, cu.course_id
                FROM CourseUnits cu
                WHERE cu.teacher_id = %s
                ORDER BY cu.course_id, cu.unit_code
            """, (teacher_db_id,))
            all_teacher_units = cursor.fetchall()

            for unit in all_teacher_units:
                if unit['course_id'] not in course_units_by_course:
                    course_units_by_course[unit['course_id']] = []
                course_units_by_course[unit['course_id']].append(unit)

    finally:
        conn.close()

    if request.method == 'POST':
        new_title = request.form['title']
        new_description = request.form.get('description')
        new_course_unit_id = request.form['course_unit_id']
        new_due_date_str = request.form['due_date']
        new_max_points = request.form['max_points']

        if not new_title or not new_course_unit_id or not new_due_date_str or not new_max_points:
            flash('All required fields must be filled.', 'danger')
            return render_template('teacher/edit_assessment.html', assessment=assessment,
                                   teacher_courses=teacher_courses, course_units_by_course=course_units_by_course)

        try:
            new_due_date = datetime.strptime(new_due_date_str, '%Y-%m-%d').date()
            new_max_points = int(new_max_points)
            if new_max_points <= 0:
                raise ValueError("Max points must be a positive number.")
        except ValueError as e:
            flash(f'Invalid input: {e}', 'danger')
            return render_template('teacher/edit_assessment.html', assessment=assessment,
                                   teacher_courses=teacher_courses, course_units_by_course=course_units_by_course)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                teacher_db_id = current_user.teacher_id
                if not teacher_db_id:
                    flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                    return redirect(url_for('dashboard'))

                # Verify that the selected new_course_unit_id is assigned to this teacher
                cursor.execute("""
                    SELECT id FROM CourseUnits
                    WHERE id = %s AND teacher_id = %s
                """, (new_course_unit_id, teacher_db_id))
                if not cursor.fetchone():
                    flash('Invalid unit selection. You are not assigned to this unit.', 'danger')
                    return render_template('teacher/edit_assessment.html', assessment=assessment,
                                           teacher_courses=teacher_courses,
                                           course_units_by_course=course_units_by_course)

                # Fetch the parent course_id from the selected course_unit_id
                cursor.execute("SELECT course_id FROM CourseUnits WHERE id = %s", (new_course_unit_id,))
                parent_course_id = cursor.fetchone()['course_id']

                # Update assessment linked to course_unit_id and its parent course_id
                sql = "UPDATE Assessments SET title = %s, description = %s, course_id = %s, course_unit_id = %s, due_date = %s, max_points = %s WHERE id = %s"
                cursor.execute(sql, (new_title, new_description, parent_course_id, new_course_unit_id, new_due_date,
                                     new_max_points, assessment_id))
                conn.commit()
                flash(f'Assessment "{new_title}" updated successfully!', 'success')
                return redirect(url_for('teacher_assessments'))
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('teacher/edit_assessment.html', assessment=assessment, teacher_courses=teacher_courses,
                           course_units_by_course=course_units_by_course)


@app.route('/teacher/assessments/delete/<int:assessment_id>', methods=['POST'])
@login_required
def teacher_delete_assessment(assessment_id):
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            # Verify that the assessment is linked to a unit taught by this teacher
            sql_check_owner = """
            SELECT a.id
            FROM Assessments a
            JOIN CourseUnits cu ON a.course_unit_id = cu.id
            WHERE a.id = %s AND cu.teacher_id = %s
            """
            cursor.execute(sql_check_owner, (assessment_id, teacher_db_id))
            if not cursor.fetchone():
                flash('Assessment not found or you do not have permission to delete it.', 'danger')
                return redirect(url_for('teacher_assessments'))

            sql = "DELETE FROM Assessments WHERE id = %s"
            cursor.execute(sql, (assessment_id,))
            conn.commit()
            flash('Assessment deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting assessment: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('teacher_assessments'))


@app.route('/teacher/submissions/<int:grade_id>/download')
@login_required
def teacher_download_submission(grade_id):
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    file_path = None
    filename = None
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            sql = """
            SELECT g.submission_file_path, u.username AS student_username, a.title AS assessment_title
            FROM Grades g
            JOIN Assessments a ON g.assessment_id = a.id
            JOIN CourseUnits cu ON a.course_unit_id = cu.id
            JOIN Students s ON g.student_id = s.id
            JOIN Users u ON s.user_id = u.id
            WHERE g.id = %s AND cu.teacher_id = %s
            """
            cursor.execute(sql, (grade_id, teacher_db_id))
            submission_data = cursor.fetchone()

            if not submission_data or not submission_data['submission_file_path']:
                flash('Submission file not found or you do not have permission to access it.', 'danger')
                return redirect(url_for('teacher_dashboard'))

            file_path = submission_data['submission_file_path']
            original_filename = os.path.basename(file_path)
            file_extension = original_filename.rsplit('.', 1)[1]
            filename = f"{submission_data['student_username']}_{submission_data['assessment_title']}.{file_extension}"
            filename = secure_filename(filename)

    except Exception as e:
        flash(f'Error preparing download: {e}', 'danger')
        return redirect(url_for('teacher_dashboard'))
    finally:
        conn.close()

    if file_path and os.path.exists(file_path):
        directory = app.config['UPLOAD_FOLDER']
        return send_from_directory(directory, os.path.basename(file_path), as_attachment=True, download_name=filename)

    flash('File could not be downloaded.', 'danger')
    return redirect(url_for('teacher_dashboard'))


@app.route('/teacher/grade_submissions')
@login_required
def teacher_grade_submissions():
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    submissions_to_grade = []
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            sql = """
            SELECT
                g.id AS grade_id, g.submission_date, g.status,
                a.title AS assessment_title, a.max_points,
                c.name AS course_name, c.code AS course_code,
                cu.unit_code, cu.unit_title,
                s.first_name AS student_first_name, s.last_name AS student_last_name,
                u.username AS student_username, g.submission_file_path
            FROM Grades g
            JOIN Assessments a ON g.assessment_id = a.id
            JOIN CourseUnits cu ON a.course_unit_id = cu.id
            JOIN Courses c ON cu.course_id = c.id
            JOIN Students s ON g.student_id = s.id
            JOIN Users u ON s.user_id = u.id
            WHERE cu.teacher_id = %s AND g.status = 'Submitted' AND g.grade IS NULL
            ORDER BY g.submission_date ASC, c.name, cu.unit_title, a.title, u.username
            """
            cursor.execute(sql, (teacher_db_id,))
            submissions_to_grade = cursor.fetchall()
    finally:
        conn.close()
    return render_template('teacher/grade_submissions.html', submissions_to_grade=submissions_to_grade)


@app.route('/teacher/grade_submission/<int:grade_id>', methods=['GET', 'POST'])
@login_required
def teacher_view_grade_submission(grade_id):
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    submission = None
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            sql = """
            SELECT
                g.id AS grade_id, g.submission_date, g.status, g.grade, g.feedback, g.submission_file_path, g.graded_date,
                a.id AS assessment_id, a.title AS assessment_title, a.description AS assessment_description, a.due_date, a.max_points,
                c.name AS course_name, c.code AS course_code,
                cu.unit_code, cu.unit_title,
                s.first_name AS student_first_name, s.last_name AS student_last_name,
                u.username AS student_username
            FROM Grades g
            JOIN Assessments a ON g.assessment_id = a.id
            JOIN CourseUnits cu ON a.course_unit_id = cu.id
            JOIN Courses c ON cu.course_id = c.id
            JOIN Students s ON g.student_id = s.id
            JOIN Users u ON s.user_id = u.id
            WHERE g.id = %s AND cu.teacher_id = %s
            """
            cursor.execute(sql, (grade_id, teacher_db_id))
            submission = cursor.fetchone()

            if not submission:
                flash('Submission not found or you do not have permission to grade it.', 'danger')
                return redirect(url_for('teacher_grade_submissions'))
    finally:
        conn.close()

    if request.method == 'POST':
        grade = request.form.get('grade')
        feedback = request.form.get('feedback')

        if not grade:
            flash('Grade is required.', 'danger')
            return render_template('teacher/grade_submission_detail.html', submission=submission)

        try:
            grade = float(grade)
            if not (0 <= grade <= submission['max_points']):
                flash(f'Grade must be between 0 and {submission["max_points"]}.', 'danger')
                return render_template('teacher/grade_submission_detail.html', submission=submission)
        except ValueError:
            flash('Invalid grade format. Please enter a number.', 'danger')
            return render_template('teacher/grade_submission_detail.html', submission=submission)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql_update = """
                UPDATE Grades
                SET grade = %s, feedback = %s, graded_date = %s, status = 'Graded'
                WHERE id = %s
                """
                cursor.execute(sql_update, (grade, feedback, datetime.now(), grade_id))
                conn.commit()
                flash('Submission graded successfully!', 'success')
                return redirect(url_for('teacher_grade_submissions'))
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()

    return render_template('teacher/grade_submission_detail.html', submission=submission)


@app.route('/teacher/graded_submissions')
@login_required
def teacher_graded_submissions():
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    graded_submissions = []
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            sql = """
            SELECT
                g.id AS grade_id, g.submission_date, g.status, g.grade, g.feedback, g.graded_date,
                a.title AS assessment_title, a.max_points,
                c.name AS course_name, c.code AS course_code,
                cu.unit_code, cu.unit_title,
                s.first_name AS student_first_name, s.last_name AS student_last_name,
                u.username AS student_username, g.submission_file_path
            FROM Grades g
            JOIN Assessments a ON g.assessment_id = a.id
            JOIN CourseUnits cu ON a.course_unit_id = cu.id
            JOIN Courses c ON cu.course_id = c.id
            JOIN Students s ON g.student_id = s.id
            JOIN Users u ON s.user_id = u.id
            WHERE cu.teacher_id = %s AND g.status = 'Graded' AND g.grade IS NOT NULL
            ORDER BY g.graded_date DESC, c.name, cu.unit_title, a.title, u.username
            """
            cursor.execute(sql, (teacher_db_id,))
            graded_submissions = cursor.fetchall()
    finally:
        conn.close()
    return render_template('teacher/graded_submissions.html', graded_submissions=graded_submissions)


@app.route('/teacher/feedback')
@login_required
def teacher_feedback_list():
    """Lists all student feedback relevant to the logged-in teacher."""
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    feedback_items = []
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            sql = """
            SELECT
                sf.id, sf.feedback_text, sf.feedback_date, sf.teacher_reply_text, sf.teacher_reply_date, sf.status,
                s.first_name AS student_first_name, s.last_name AS student_last_name,
                u.username AS student_username,
                c.name AS course_name, c.code AS course_code
            FROM StudentFeedback sf
            JOIN Students s ON sf.student_id = s.id
            JOIN Users u ON s.user_id = u.id
            LEFT JOIN Courses c ON sf.course_id = c.id
            WHERE sf.teacher_id = %s
            ORDER BY sf.feedback_date DESC
            """
            cursor.execute(sql, (teacher_db_id,))
            feedback_items = cursor.fetchall()
    finally:
        conn.close()
    return render_template('teacher/feedback_list.html', feedback_items=feedback_items)


@app.route('/teacher/feedback/<int:feedback_id>', methods=['GET', 'POST'])
@login_required
def teacher_reply_feedback(feedback_id):
    """Allows a teacher to view and reply to a specific student feedback."""
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    feedback_item = None
    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            sql = """
            SELECT
                sf.id, sf.feedback_text, sf.feedback_date, sf.teacher_reply_text, sf.teacher_reply_date, sf.status,
                s.first_name AS student_first_name, s.last_name AS student_last_name,
                u.username AS student_username,
                c.name AS course_name, c.code AS course_code,
                t.id AS teacher_db_id
            FROM StudentFeedback sf
            JOIN Students s ON sf.student_id = s.id
            JOIN Users u ON s.user_id = u.id
            LEFT JOIN Courses c ON sf.course_id = c.id
            LEFT JOIN Teachers t ON sf.teacher_id = t.id
            WHERE sf.id = %s AND sf.teacher_id = %s
            """
            cursor.execute(sql, (feedback_id, teacher_db_id))
            feedback_item = cursor.fetchone()

            if not feedback_item:
                flash('Feedback not found or you do not have permission to view/reply to it.', 'danger')
                return redirect(url_for('teacher_feedback_list'))
    finally:
        conn.close()

    if request.method == 'POST':
        teacher_reply_text = request.form.get('teacher_reply_text')

        if not teacher_reply_text:
            flash('Reply text cannot be empty.', 'danger')
            return render_template('teacher/reply_feedback.html', feedback_item=feedback_item)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql_update = """
                UPDATE StudentFeedback
                SET teacher_reply_text = %s, teacher_reply_date = %s, status = 'Replied', teacher_id = %s
                WHERE id = %s
                """
                cursor.execute(sql_update, (teacher_reply_text, datetime.now(), current_user.teacher_id, feedback_id))
                conn.commit()
                flash('Reply sent successfully!', 'success')
                return redirect(url_for('teacher_feedback_list'))
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()

    return render_template('teacher/reply_feedback.html', feedback_item=feedback_item)


@app.route('/teacher/courses/<int:course_id>/roster')
@login_required
def teacher_course_roster(course_id):
    """Allows a teacher to view the list of students enrolled in a specific course they teach,
    and the units they teach within that course."""
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    course_info = None
    enrolled_students = []
    teacher_units_in_course = []  # New variable to hold units taught by this teacher in this course

    try:
        with conn.cursor() as cursor:
            teacher_db_id = current_user.teacher_id
            if not teacher_db_id:
                flash('Your teacher profile is not fully set up. Please contact an administrator.', 'danger')
                return redirect(url_for('dashboard'))

            # Check if the teacher is assigned to any unit in this course
            sql_course_check = """
            SELECT DISTINCT c.id, c.name, c.code
            FROM Courses c
            JOIN CourseUnits cu ON c.id = cu.course_id
            WHERE c.id = %s AND cu.teacher_id = %s
            """
            cursor.execute(sql_course_check, (course_id, teacher_db_id))
            course_info = cursor.fetchone()

            if not course_info:
                flash('Course not found or you do not teach any units in this course.', 'danger')
                return redirect(url_for('teacher_dashboard'))

            # Fetch students enrolled in this course
            sql_students = """
            SELECT
                s.id AS student_db_id, s.first_name, s.last_name, u.username,
                sce.enrollment_date, sce.status AS enrollment_status
            FROM StudentCourseEnrollments sce
            JOIN Students s ON sce.student_id = s.id
            JOIN Users u ON s.user_id = u.id
            WHERE sce.course_id = %s
            ORDER BY s.last_name, s.first_name
            """
            cursor.execute(sql_students, (course_id,))
            enrolled_students = cursor.fetchall()

            # NEW: Fetch units that the current teacher teaches within this specific course
            sql_teacher_units = """
            SELECT cu.id, cu.unit_code, cu.unit_title, cu.credit_points, cu.semester, cu.prerequisites
            FROM CourseUnits cu
            WHERE cu.course_id = %s AND cu.teacher_id = %s
            ORDER BY cu.semester, cu.unit_code
            """
            cursor.execute(sql_teacher_units, (course_id, teacher_db_id))
            teacher_units_in_course = cursor.fetchall()

    finally:
        conn.close()
    return render_template('teacher/course_roster.html',
                           course_info=course_info,
                           enrolled_students=enrolled_students,
                           teacher_units_in_course=teacher_units_in_course)  # Pass new variable


# --- Student Routes ---
@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Access denied. You do not have student privileges.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    student_info = None
    grades = []
    feedback_history = []
    upcoming_assessments = []
    enrolled_courses = []
    try:
        with conn.cursor() as cursor:
            sql_student_info = """
            SELECT s.first_name, s.last_name, p.name AS program_name, p.id AS program_id
            FROM Students s
            LEFT JOIN Programs p ON s.program_id = p.id
            WHERE s.user_id = %s
            """
            cursor.execute(sql_student_info, (current_user.id,))
            student_info = cursor.fetchone()

            if student_info and student_info['program_id']:
                sql_upcoming_assessments = """
                SELECT DISTINCT
                    a.id, a.title, a.description, a.due_date, a.max_points,
                    c.name AS course_name, c.code AS course_code,
                    cu.unit_code, cu.unit_title,
                    t_unit.first_name AS unit_teacher_first_name, t_unit.last_name AS unit_teacher_last_name,
                    CASE WHEN g.status IS NOT NULL THEN g.status ELSE 'Not Submitted' END AS submission_status
                FROM Assessments a
                JOIN Courses c ON a.course_id = c.id
                LEFT JOIN CourseUnits cu ON a.course_unit_id = cu.id
                LEFT JOIN Teachers t_unit ON cu.teacher_id = t_unit.id
                LEFT JOIN Grades g ON a.id = g.assessment_id AND g.student_id = %s
                WHERE c.program_id = %s AND (g.status IS NULL OR g.status != 'Graded')
                ORDER BY a.due_date ASC, c.name, cu.unit_title, a.title
                """
                cursor.execute(sql_upcoming_assessments, (current_user.student_id, student_info['program_id']))
                upcoming_assessments = cursor.fetchall()

            # FIX: Added a.id AS assessment_id to the SELECT for grades
            sql_grades = """
            SELECT a.id AS assessment_id, a.title AS assessment_title, c.name AS course_name, g.grade, g.feedback, g.graded_date, g.status AS submission_status, a.max_points,
                   cu.unit_code, cu.unit_title
            FROM Grades g
            JOIN Assessments a ON g.assessment_id = a.id
            JOIN Courses c ON a.course_id = c.id
            LEFT JOIN CourseUnits cu ON a.course_unit_id = cu.id
            WHERE g.student_id = %s AND g.status = 'Graded' AND g.grade IS NOT NULL
            ORDER BY g.graded_date DESC
            """
            cursor.execute(sql_grades, (current_user.student_id,))
            grades = cursor.fetchall()

            sql_feedback = """
            SELECT sf.id, sf.feedback_text, sf.feedback_date, sf.teacher_reply_text, sf.teacher_reply_date, sf.status,
                   t.first_name AS teacher_first_name, t.last_name AS teacher_last_name,
                   c.name AS course_name, c.code AS course_code
            FROM StudentFeedback sf
            LEFT JOIN Teachers t ON sf.teacher_id = t.id
            LEFT JOIN Courses c ON sf.course_id = c.id
            WHERE sf.student_id = %s
            ORDER BY sf.feedback_date DESC
            """
            cursor.execute(sql_feedback, (current_user.student_id,))
            feedback_history = cursor.fetchall()

            # Enrolled courses will be those explicitly linked to the student
            sql_enrolled_courses = """
            SELECT DISTINCT c.id, c.name, c.code, c.description,
                   t_coord.first_name AS coordinator_first_name, t_coord.last_name AS coordinator_last_name
            FROM Courses c
            JOIN StudentCourseEnrollments sce ON c.id = sce.course_id
            LEFT JOIN Teachers t_coord ON c.teacher_id = t_coord.id
            WHERE sce.student_id = %s AND sce.status = 'Enrolled'
            ORDER BY c.name
            """
            cursor.execute(sql_enrolled_courses, (current_user.student_id,))
            enrolled_courses = cursor.fetchall()


    finally:
        conn.close()

    return render_template('student/dashboard.html',
                           student_info=student_info,
                           grades=grades,
                           feedback_history=feedback_history,
                           upcoming_assessments=upcoming_assessments,
                           enrolled_courses=enrolled_courses)


@app.route('/student/courses')  # NEW ROUTE FOR STUDENT COURSE OVERVIEW
@login_required
def student_courses():
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    enrolled_courses = []
    try:
        with conn.cursor() as cursor:
            sql_enrolled_courses = """
            SELECT DISTINCT c.id, c.name, c.code, c.description,
                   t_coord.first_name AS coordinator_first_name, t_coord.last_name AS coordinator_last_name
            FROM Courses c
            JOIN StudentCourseEnrollments sce ON c.id = sce.course_id
            LEFT JOIN Teachers t_coord ON c.teacher_id = t_coord.id
            WHERE sce.student_id = %s AND sce.status = 'Enrolled'
            ORDER BY c.name
            """
            cursor.execute(sql_enrolled_courses, (current_user.student_id,))
            enrolled_courses = cursor.fetchall()
    finally:
        conn.close()

    return render_template('student/courses.html', enrolled_courses=enrolled_courses)


@app.route('/student/assessments')
@login_required
def student_view_all_assessments():  # Renamed from student_assessments
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    all_assessments = []
    try:
        with conn.cursor() as cursor:
            # We fetch assessments linked to courses the student is *enrolled* in
            # as well as any assessments from their *program* even if not explicitly enrolled in that course (for broader view)
            sql = """
            SELECT DISTINCT
                a.id, a.title, a.description, a.due_date, a.max_points,
                c.name AS course_name, c.code AS course_code,
                cu.unit_code, cu.unit_title,
                t_unit.first_name AS unit_teacher_first_name, t_unit.last_name AS unit_teacher_last_name,
                g.status AS submission_status, g.grade, g.graded_date, g.submission_file_path, g.id AS grade_id
            FROM Assessments a
            JOIN Courses c ON a.course_id = c.id
            LEFT JOIN CourseUnits cu ON a.course_unit_id = cu.id
            LEFT JOIN Teachers t_unit ON cu.teacher_id = t_unit.id
            LEFT JOIN Grades g ON a.id = g.assessment_id AND g.student_id = %s
            WHERE c.id IN (SELECT course_id FROM StudentCourseEnrollments WHERE student_id = %s)
            ORDER BY a.due_date DESC, c.name, cu.unit_title, a.title
            """
            cursor.execute(sql, (current_user.student_id, current_user.student_id))
            all_assessments = cursor.fetchall()

    finally:
        conn.close()
    return render_template('student/assessments.html',
                           all_assessments=all_assessments)  # Note: this still uses student/assessments.html


@app.route('/student/assessments/<int:assessment_id>')
@login_required
def student_view_assessment(assessment_id):
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    assessment = None
    student_grade_info = None
    try:
        with conn.cursor() as cursor:
            # Crucially, check if the student is enrolled in the course associated with this assessment
            sql_assessment = """
            SELECT
                a.id, a.title, a.description, a.due_date, a.max_points,
                c.name AS course_name, c.code AS course_code,
                cu.unit_code, cu.unit_title,
                t_unit.first_name AS unit_teacher_first_name, t_unit.last_name AS unit_teacher_last_name
            FROM Assessments a
            JOIN Courses c ON a.course_id = c.id
            LEFT JOIN CourseUnits cu ON a.course_unit_id = cu.id
            LEFT JOIN Teachers t_unit ON cu.teacher_id = t_unit.id
            WHERE a.id = %s
              AND c.id IN (SELECT course_id FROM StudentCourseEnrollments WHERE student_id = %s)
            """
            cursor.execute(sql_assessment, (assessment_id, current_user.student_id))
            assessment = cursor.fetchone()

            if not assessment:
                flash('Assessment not found or not accessible to you.', 'danger')
                return redirect(url_for('student_view_all_assessments'))  # Redirect to the general assessments page

            sql_grade_info = """
            SELECT id AS grade_id, grade, feedback, graded_date, submission_date, status, submission_file_path
            FROM Grades
            WHERE assessment_id = %s AND student_id = %s
            """
            cursor.execute(sql_grade_info, (assessment_id, current_user.student_id))
            student_grade_info = cursor.fetchone()

    finally:
        conn.close()
    return render_template('student/view_assessment.html', assessment=assessment, student_grade_info=student_grade_info)


@app.route('/student/assessments/<int:assessment_id>/submit', methods=['POST'])
@login_required
def student_submit_assessment(assessment_id):
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    file_path = None
    try:
        with conn.cursor() as cursor:
            # Check if the student is enrolled in the course associated with this assessment
            sql_check_assessment = """
            SELECT a.id
            FROM Assessments a
            JOIN Courses c ON a.course_id = c.id
            WHERE a.id = %s AND c.id IN (SELECT course_id FROM StudentCourseEnrollments WHERE student_id = %s)
            """
            cursor.execute(sql_check_assessment, (assessment_id, current_user.student_id))
            if not cursor.fetchone():
                flash('Assessment not found or not accessible for submission.', 'danger')
                return redirect(url_for('student_view_all_assessments'))

            if 'submission_file' not in request.files:
                flash('No file part in the request.', 'danger')
                return redirect(url_for('student_view_assessment', assessment_id=assessment_id))

            file = request.files['submission_file']
            if file.filename == '':
                flash('No selected file.', 'warning')
                return redirect(url_for('student_view_assessment', assessment_id=assessment_id))

            if not allowed_file(file.filename):
                flash('Invalid file type. Only .doc, .docx, and .pdf files are allowed.', 'danger')
                return redirect(url_for('student_view_assessment', assessment_id=assessment_id))

            original_filename = secure_filename(file.filename)
            unique_filename = f"{current_user.username}_{assessment_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{original_filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)

            cursor.execute(
                "SELECT id, status, submission_file_path FROM Grades WHERE assessment_id = %s AND student_id = %s",
                (assessment_id, current_user.student_id))
            existing_grade = cursor.fetchone()

            if existing_grade:
                if existing_grade['status'] == 'Graded':
                    flash('This assessment has already been graded and cannot be resubmitted.', 'info')
                    if file_path and os.path.exists(file_path):
                        os.remove(file_path)
                else:
                    if existing_grade['submission_file_path'] and os.path.exists(
                            existing_grade['submission_file_path']):
                        os.remove(existing_grade['submission_file_path'])
                    sql_update = "UPDATE Grades SET submission_date = %s, status = 'Submitted', submission_file_path = %s WHERE id = %s"
                    cursor.execute(sql_update, (datetime.now(), file_path, existing_grade['id']))
                    flash('Assessment submitted successfully!', 'success')
            else:
                sql_insert = "INSERT INTO Grades (assessment_id, student_id, submission_date, status, submission_file_path) VALUES (%s, %s, %s, 'Submitted', %s)"
                cursor.execute(sql_insert, (assessment_id, current_user.student_id, datetime.now(), file_path))
                flash('Assessment submitted successfully!', 'success')

            conn.commit()

    except Exception as e:
        conn.rollback()
        flash(f'Error submitting assessment: {e}', 'danger')
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
    finally:
        conn.close()
    return redirect(url_for('student_view_assessment', assessment_id=assessment_id))


@app.route('/student/feedback/add', methods=['GET', 'POST'])
@login_required
def student_add_feedback():
    """Allows a student to submit feedback to a teacher or generally."""
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    teachers = []
    courses = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, first_name, last_name FROM Teachers ORDER BY first_name")
            teachers = cursor.fetchall()
            # Fetch courses the student is *enrolled* in for feedback
            cursor.execute("""
                SELECT c.id, c.name, c.code
                FROM Courses c
                JOIN StudentCourseEnrollments sce ON c.id = sce.course_id
                WHERE sce.student_id = %s
                ORDER BY c.name
            """, (current_user.student_id,))
            courses = cursor.fetchall()
    finally:
        conn.close()

    if request.method == 'POST':
        feedback_text = request.form['feedback_text']
        teacher_id = request.form.get('teacher_id')
        course_id = request.form.get('course_id')

        if not feedback_text:
            flash('Feedback text cannot be empty.', 'danger')
            return render_template('student/add_feedback.html', teachers=teachers, courses=courses)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = """
                INSERT INTO StudentFeedback (student_id, teacher_id, course_id, feedback_text, feedback_date, status)
                VALUES (%s, %s, %s, %s, %s, 'New')
                """
                cursor.execute(sql, (current_user.student_id, teacher_id if teacher_id else None,
                                     course_id if course_id else None, feedback_text, datetime.now()))
                conn.commit()
                flash('Feedback submitted successfully!', 'success')
                return redirect(url_for('student_dashboard'))
        except Exception as e:
            conn.rollback()
            flash(f'Error submitting feedback: {e}', 'danger')
        finally:
            conn.close()
    return render_template('student/add_feedback.html', teachers=teachers, courses=courses)


@app.route('/student/feedback/<int:feedback_id>')
@login_required
def student_view_feedback(feedback_id):
    """Allows a student to view a specific feedback item and its reply."""
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    feedback_item = None
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT sf.id, sf.feedback_text, sf.feedback_date, sf.teacher_reply_text, sf.teacher_reply_date, sf.status,
                   t.first_name AS teacher_first_name, t.last_name AS teacher_last_name,
                   c.name AS course_name, c.code AS course_code
            FROM StudentFeedback sf
            LEFT JOIN Teachers t ON sf.teacher_id = t.id
            LEFT JOIN Courses c ON sf.course_id = c.id
            WHERE sf.id = %s AND sf.student_id = %s
            """
            cursor.execute(sql, (feedback_id, current_user.student_id))
            feedback_item = cursor.fetchone()

            if not feedback_item:
                flash('Feedback not found or not accessible to you.', 'danger')
                return redirect(url_for('student_dashboard'))
    finally:
        conn.close()
    return render_template('student/view_feedback.html', feedback_item=feedback_item)


@app.route('/student/grades_transcript')
@login_required
def student_grades_transcript():
    """Allows a student to view a comprehensive list of all their graded assessments."""
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    graded_assessments = []
    student_info = None  # To display student's name on the transcript page

    try:
        with conn.cursor() as cursor:
            # Fetch student's name for display
            cursor.execute("SELECT first_name, last_name FROM Students WHERE user_id = %s", (current_user.id,))
            student_info = cursor.fetchone()

            # Fetch all graded assessments for the current student
            sql_graded_assessments = """
            SELECT
                g.id AS grade_id,
                a.title AS assessment_title,
                a.max_points,
                g.grade,
                g.feedback,
                g.graded_date,
                g.submission_date,
                c.name AS course_name,
                c.code AS course_code,
                cu.unit_code,
                cu.unit_title,
                t.first_name AS teacher_first_name,
                t.last_name AS teacher_last_name
            FROM Grades g
            JOIN Assessments a ON g.assessment_id = a.id
            JOIN Courses c ON a.course_id = c.id
            LEFT JOIN CourseUnits cu ON a.course_unit_id = cu.id
            LEFT JOIN Teachers t ON cu.teacher_id = t.id
            WHERE g.student_id = %s AND g.status = 'Graded' AND g.grade IS NOT NULL
            ORDER BY c.name, cu.unit_code, a.due_date
            """
            cursor.execute(sql_graded_assessments, (current_user.student_id,))
            graded_assessments = cursor.fetchall()

    finally:
        conn.close()

    return render_template('student/grades_transcript.html',
                           student_info=student_info,
                           graded_assessments=graded_assessments)


@app.route('/student/courses/<int:course_id>/details')
@login_required
def student_view_course_details(course_id):
    """Allows a student to view detailed information about a specific course, including its units."""
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    course_details = None
    course_units = []
    try:
        with conn.cursor() as cursor:
            # Ensure the student is actually enrolled in this course
            sql_course_details = """
            SELECT
                c.id, c.name, c.code, c.description,
                p.name AS program_name,
                t_coord.first_name AS coordinator_first_name, t_coord.last_name AS coordinator_last_name
            FROM Courses c
            JOIN StudentCourseEnrollments sce ON c.id = sce.course_id
            LEFT JOIN Programs p ON c.program_id = p.id
            LEFT JOIN Teachers t_coord ON c.teacher_id = t_coord.id
            WHERE c.id = %s AND sce.student_id = %s
            """
            cursor.execute(sql_course_details, (course_id, current_user.student_id))
            course_details = cursor.fetchone()

            if not course_details:
                flash('Course not found or not accessible to you.', 'danger')
                return redirect(url_for('student_courses'))  # Redirect to the new student courses list

            sql_course_units = """
            SELECT cu.id, cu.unit_code, cu.unit_title, cu.credit_points, cu.prerequisites, cu.semester,
                   t.first_name AS teacher_first_name, t.last_name AS teacher_last_name
            FROM CourseUnits cu
            LEFT JOIN Teachers t ON cu.teacher_id = t.id
            WHERE cu.course_id = %s
            ORDER BY
                CASE cu.semester
                    WHEN 'SEMESTER I' THEN 1
                    WHEN 'SEMESTER II' THEN 2
                    WHEN 'SEMESTER III' THEN 3
                    WHEN 'SEMESTER IV' THEN 4
                    ELSE 99
                END,
                cu.unit_code
            """
            cursor.execute(sql_course_units, (course_id,))
            course_units = cursor.fetchall()

            grouped_units = {}
            for unit in course_units:
                semester = unit['semester']
                if semester not in grouped_units:
                    grouped_units[semester] = []
                grouped_units[semester].append(unit)

            # Custom sorting for semesters to ensure 'SEMESTER I', 'SEMESTER II' etc. are in order
            def sort_key_semester(s):
                if 'I' in s and 'II' not in s and 'III' not in s and 'IV' not in s: return 1
                if 'II' in s and 'III' not in s and 'IV' not in s: return 2
                if 'III' in s and 'IV' not in s: return 3
                if 'IV' in s: return 4
                return 99  # For any other semesters

            ordered_semesters = sorted(grouped_units.keys(), key=sort_key_semester)

    finally:
        conn.close()
    return render_template('student/view_course_details.html',
                           course_details=course_details,
                           grouped_units=grouped_units,
                           ordered_semesters=ordered_semesters)


# --- Main entry point to run the Flask application ---
if __name__ == '__main__':
    app.run(debug=True)
