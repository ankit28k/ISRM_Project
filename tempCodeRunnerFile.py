"""
ISRM Project - PATCHED Student Management System
Security controls applied: Input validation, parameterized queries, secure auth,
proper access control, logging, file validation, role-based access.
"""

from flask import Flask, request, session, render_template_string, redirect, url_for
import sqlite3
import os
import hashlib
import secrets
import logging
import re
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
# FIX 1: Strong, randomly generated secret key (not hardcoded)
app.secret_key = secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# FIX 2: Proper logging configured for audit trail
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("audit.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

DB_PATH = "students_secure.db"
UPLOAD_FOLDER = "secure_uploads"
ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx", "png", "jpg"}
MAX_LOGIN_ATTEMPTS = 5
login_attempts = {}  # In production, use Redis or DB

# ─── Helpers ───────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """FIX 3: Use SHA-256 hashing with salt (in prod, use bcrypt)."""
    salt = "isrm_salt_2024"
    return hashlib.sha256((password + salt).encode()).hexdigest()


def allowed_file(filename: str) -> bool:
    """FIX 4: Validate file extension before saving."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            logger.warning("Unauthenticated access attempt to %s", request.path)
            return redirect("/")
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session or session.get("role") != "admin":
            logger.warning("Unauthorized admin access attempt by user %s", session.get("user"))
            return "Access denied", 403
        return f(*args, **kwargs)
    return decorated

# ─── Database Setup ────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            name TEXT,
            roll_no TEXT,
            marks INTEGER,
            address TEXT,
            owner_id INTEGER
        )
    """)
    # FIX 5: Passwords are hashed, not stored in plaintext
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'admin')",
              (hash_password("Admin@2024!"),))
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'student', ?, 'user')",
              (hash_password("Student@2024!"),))
    c.execute("INSERT OR IGNORE INTO students VALUES (1,'Alice','CS001',92,'10 Main St',2)")
    c.execute("INSERT OR IGNORE INTO students VALUES (2,'Bob','CS002',78,'22 Oak Ave',2)")
    conn.commit()
    conn.close()

# ─── HTML Templates ────────────────────────────────────────────────────────────

LOGIN_PAGE = """
<html><body>
<h2>Student Management - Secure Login</h2>
<form method="POST">
  Username: <input name="username" maxlength="50" autocomplete="off"><br>
  Password: <input name="password" type="password" maxlength="100"><br>
  <input type="submit" value="Login">
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</body></html>
"""

DASHBOARD = """
<html><body>
<h2>Welcome {{ user }}! Role: {{ role }}</h2>
<a href="/students">View Students</a> |
<a href="/search">Search</a> |
<a href="/upload">Upload</a>
{% if role == 'admin' %} | <a href="/admin">Admin Panel</a>{% endif %} |
<a href="/logout">Logout</a>
</body></html>
"""

SEARCH_PAGE = """
<html><body>
<h2>Search Students</h2>
<form method="POST">
  Search: <input name="query" maxlength="100">
  <input type="submit" value="Search">
</form>
{% if results %}
<table border=1>
<tr><th>ID</th><th>Name</th><th>Roll</th><th>Marks</th></tr>
{% for r in results %}
<tr><td>{{r[0]}}</td><td>{{r[1]|e}}</td><td>{{r[2]|e}}</td><td>{{r[3]}}</td></tr>
{% endfor %}
</table>
{% endif %}
{% if error %}<p style="color:red">Input validation error</p>{% endif %}
</body></html>
"""

UPLOAD_PAGE = """
<html><body>
<h2>Upload Student Document</h2>
<p>Allowed: PDF, DOCX, XLSX, PNG, JPG only</p>
<form method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <input type="submit" value="Upload">
</form>
{% if msg %}<p>{{ msg }}</p>{% endif %}
</body></html>
"""

ADMIN_PAGE = """
<html><body>
<h2>Admin Panel (Restricted)</h2>
<h3>User List (no passwords shown):</h3>
{% for u in users %}
<p>ID: {{ u[0] }}, Username: {{ u[1]|e }}, Role: {{ u[3] }}</p>
{% endfor %}
</body></html>
"""

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # FIX 6: Input validation - reject suspicious characters
        if not re.match(r"^[a-zA-Z0-9_]{1,50}$", username):
            logger.warning("Invalid username format attempted: %s", username[:20])
            return render_template_string(LOGIN_PAGE, error="Invalid input"), 400

        # FIX 7: Brute-force lockout
        ip = request.remote_addr
        attempts = login_attempts.get(ip, 0)
        if attempts >= MAX_LOGIN_ATTEMPTS:
            logger.warning("Account lockout triggered for IP: %s", ip)
            return render_template_string(LOGIN_PAGE,
                error="Too many failed attempts. Try again later."), 429

        # FIX 8: Parameterized query prevents SQL injection
        conn = sqlite3.connect(DB_PATH)
        result = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if result and result[2] == hash_password(password):
            login_attempts[ip] = 0
            session.regenerate() if hasattr(session, 'regenerate') else None
            session["user"] = result[1]
            session["role"] = result[3]
            session["uid"] = result[0]
            logger.info("Successful login: user=%s ip=%s", username, ip)
            return redirect("/dashboard")
        else:
            login_attempts[ip] = attempts + 1
            logger.warning("Failed login attempt: user=%s ip=%s", username, ip)
            error = "Invalid credentials"

    return render_template_string(LOGIN_PAGE, error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string(DASHBOARD, user=session["user"], role=session["role"])


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    results, error = [], None
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        # FIX 9: Validate and sanitize search input
        if not re.match(r"^[a-zA-Z0-9\s\-]{0,100}$", query):
            error = "Invalid search input"
        else:
            conn = sqlite3.connect(DB_PATH)
            # FIX 10: Parameterized query
            results = conn.execute(
                "SELECT id, name, roll_no, marks FROM students WHERE name LIKE ? OR roll_no LIKE ?",
                (f"%{query}%", f"%{query}%")
            ).fetchall()
            conn.close()
            logger.info("Search performed by user=%s query=%s", session["user"], query)
    return render_template_string(SEARCH_PAGE, results=results, error=error)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    msg = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # FIX 11: Validate file type
            if not allowed_file(f.filename):
                logger.warning("Blocked file upload: %s by user=%s", f.filename, session["user"])
                msg = "File type not allowed."
            else:
                # FIX 12: Sanitize filename to prevent path traversal
                filename = secure_filename(f.filename)
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                f.save(filepath)
                logger.info("File uploaded: %s by user=%s", filename, session["user"])
                msg = f"File '{filename}' uploaded successfully."
    return render_template_string(UPLOAD_PAGE, msg=msg)


@app.route("/admin", methods=["GET"])
@admin_required  # FIX 13: Role-based access control
def admin_panel():
    conn = sqlite3.connect(DB_PATH)
    # FIX 14: Never expose password hashes; only show username and role
    users = conn.execute("SELECT id, username, '', role FROM users").fetchall()
    conn.close()
    logger.info("Admin panel accessed by user=%s", session["user"])
    # FIX 15: NO command execution endpoint
    return render_template_string(ADMIN_PAGE, users=users)


@app.route("/student/<int:student_id>")
@login_required
def get_student(student_id):
    # FIX 16: IDOR prevention - check ownership unless admin
    conn = sqlite3.connect(DB_PATH)
    if session["role"] == "admin":
        student = conn.execute(
            "SELECT id, name, roll_no, marks FROM students WHERE id = ?",
            (student_id,)
        ).fetchone()
    else:
        student = conn.execute(
            "SELECT id, name, roll_no, marks FROM students WHERE id = ? AND owner_id = ?",
            (student_id, session["uid"])
        ).fetchone()
    conn.close()
    if student:
        return f"<pre>{student}</pre>"
    return "Not found or access denied", 404


@app.route("/api/data")
@login_required  # FIX 17: API requires authentication
def api_data():
    conn = sqlite3.connect(DB_PATH)
    # Return only non-sensitive fields
    data = conn.execute("SELECT id, name, roll_no, marks FROM students").fetchall()
    conn.close()
    return {"students": [list(r) for r in data]}


@app.route("/logout")
def logout():
    user = session.get("user", "unknown")
    session.clear()
    logger.info("User logged out: %s", user)
    return redirect("/")


if __name__ == "__main__":
    init_db()
    # FIX 18: Debug mode disabled in production
    app.run(debug=False, host="127.0.0.1", port=5000)
