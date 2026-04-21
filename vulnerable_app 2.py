"""
ISRM Project - Vulnerable Student Management System
WARNING: This file contains INTENTIONAL vulnerabilities for educational purposes.
DO NOT deploy in production.
"""

from flask import Flask, request, session, render_template_string, redirect, url_for,send_from_directory
import sqlite3
import os
import subprocess
import hashlib
import pickle
import logging

app = Flask(__name__)
app.secret_key = "admin123"  # VULNERABILITY: Hardcoded weak secret key

# VULNERABILITY: Logging disabled - no audit trail (Repudiation)
# logging.basicConfig(level=logging.INFO)

DB_PATH = "students.db"

# ─── Database Setup ────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            name TEXT,
            roll_no TEXT,
            marks INTEGER,
            address TEXT
        )
    """)
    # VULNERABILITY: Plaintext passwords stored (Information Disclosure)
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'student', 'pass123', 'user')")
    c.execute("INSERT OR IGNORE INTO students VALUES (1, 'Alice', 'CS001', 92, '10 Main St')")
    c.execute("INSERT OR IGNORE INTO students VALUES (2, 'Bob', 'CS002', 78, '22 Oak Ave')")
    conn.commit()
    conn.close()

# ─── HTML Templates ────────────────────────────────────────────────────────────

LOGIN_PAGE = """
<html>
<head>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
body { background:#0f172a; color:#e2e8f0; }

input::placeholder {
  color: #94a3b8 !important;
  opacity: 1;
}

input {
  color: white !important;
}

</style>
</head>

<body class="d-flex justify-content-center align-items-center vh-100">

<div class="card p-4 shadow-lg" style="width:350px;">
<h3 class="text-center mb-3">🔐 Login</h3>

<form method="POST">
<input class="form-control mb-2 bg-dark text-white border-0" 
       style="color:white !important;" 
       name="username" placeholder="Username">

<input class="form-control mb-3 bg-dark text-white border-0" 
       style="color:white !important;" 
       name="password" type="password" placeholder="Password">
<button class="btn btn-primary w-100">Login</button>
</form>

{% if error %}
<div class="alert alert-danger mt-2">{{ error }}</div>
{% endif %}
</div>

</body>
</html>
"""

DASHBOARD = """
<html>
<head>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
body {
  background:#0f172a;
  color:#e2e8f0;
}

/* Card style */
.option-card {
  background:#1e293b;
  border-radius:12px;
  height:220px;              /* 🔥 increase height */
  display:flex;
  flex-direction:column;
  justify-content:center;    /* center content vertically */
  align-items:center;
  transition: all 0.3s ease;
  box-shadow: 0 4px 20px rgba(0,0,0,0.4);
  cursor:pointer;
}

.option-card h4 {
  margin-top:10px;
  font-weight:500;
}

.icon {
  font-size:32px;
}

/* Hover animation */
.option-card:hover {
  transform: translateY(-8px) scale(1.02);
  box-shadow: 0 10px 30px rgba(0,0,0,0.7);
}

/* Icons */
.icon {
  font-size:28px;
  margin-bottom:10px;
}

/* Colors */
.search { border-left: 5px solid #6366f1; }
.upload { border-left: 5px solid #22c55e; }
.admin { border-left: 5px solid #facc15; }
.logout { border-left: 5px solid #ef4444; }

a {
  text-decoration:none;
  color:inherit;
}
</style>

</head>

<body>

<div class="container mt-5">

<h2 class="mb-4">Dashboard</h2>

<div class="row g-4">

  <div class="col-md-6">
    <a href="/search">
      <div class="option-card search">
        <div class="icon">🔍</div>
        <h4>Search Students</h4>
      </div>
    </a>
  </div>

  <div class="col-md-6">
    <a href="/upload">
      <div class="option-card upload">
        <div class="icon">📁</div>
        <h4>Upload File</h4>
      </div>
    </a>
  </div>

  <div class="col-md-6">
    <a href="/admin">
      <div class="option-card admin">
        <div class="icon">⚙️</div>
        <h4>Admin Panel</h4>
      </div>
    </a>
  </div>

  <div class="col-md-6">
    <a href="/logout">
      <div class="option-card logout">
        <div class="icon">🚪</div>
        <h4>Logout</h4>
      </div>
    </a>
  </div>

</div>

</div>

</body>
</html>
"""

SEARCH_PAGE = """
<html>
<head>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
body {
  background:#0f172a;
  color:#e2e8f0;
}

/* Card container */
.card-box {
  background:#1e293b;
  border-radius:12px;
  padding:25px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.4);
}

/* Input styling */
input {
  background:#020617 !important;
  color:white !important;
  border:none !important;
}

/* Placeholder */
input::placeholder {
  color:#94a3b8 !important;
}

/* Table styling */
.table {
  color:white;
}

.table tbody tr {
  transition: 0.3s;
}

/* Hover effect */
.table tbody tr:hover {
  background:#334155;
  transform: scale(1.01);
}

/* Button hover */
.btn-primary:hover {
  transform: scale(1.05);
}
</style>

</head>

<body>

<div class="container mt-5">

<div class="card-box">

<h3 class="mb-4">🔍 Search Students</h3>

<form method="POST">
  <div class="row">
    <div class="col-md-9">
      <input class="form-control" name="query" placeholder="Enter name or roll number">
    </div>
    <div class="col-md-3">
      <button class="btn btn-primary w-100">Search</button>
    </div>
  </div>
</form>

{% if results %}
<table class="table table-dark table-striped mt-4">
<tr>
<th>ID</th><th>Name</th><th>Roll</th><th>Marks</th><th>Address</th>
</tr>

{% for r in results %}
<tr>
<td>{{r[0]}}</td>
<td>{{r[1]}}</td>
<td>{{r[2]}}</td>
<td>{{r[3]}}</td>
<td>{{r[4]}}</td>
</tr>
{% endfor %}

</table>
{% endif %}

{% if error %}
<div class="alert alert-danger mt-3">{{ error }}</div>
{% endif %}

</div>

</div>

</body>
</html>
"""


UPLOAD_PAGE = """
<html>
<head>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
body {
  background:#0f172a;
  color:#e2e8f0;
}

/* Card */
.card-box {
  background:#1e293b;
  border-radius:12px;
  padding:30px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.4);
}

/* File input */
input[type="file"] {
  background:#020617;
  color:white;
  border:none;
  padding:10px;
}

/* Button hover */
.btn-success {
  transition: 0.3s;
}

.btn-success:hover {
  transform: scale(1.05);
  box-shadow: 0 5px 20px rgba(34,197,94,0.5);
}

/* Message box */
.alert {
  background:#020617;
  color:#22c55e;
  border:none;
}
</style>

</head>

<body>

<div class="container mt-5">

<div class="card-box">

<h3 class="mb-4">📁 Upload File</h3>

<form method="POST" enctype="multipart/form-data">
  
  <div class="mb-3">
    <input class="form-control" type="file" name="file">
  </div>

  <button class="btn btn-success">Upload</button>

</form>

{% if msg %}
<div class="alert mt-4">{{ msg }}</div>
{% endif %}

</div>

</div>

</body>
</html>
"""

ADMIN_PAGE = """
<html>
<head>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body { background:#020617; color:#e2e8f0; }
</style>
</head>

<body>
<div class="container mt-4">

<div class="card p-4 shadow" style="background:#1e293b;">
<h3 class="text-danger">⚠️ Admin Panel</h3>

<form method="POST">
<input class="form-control bg-dark text-white border-0" name="cmd" placeholder="Enter command">
<button class="btn btn-danger mt-2">Execute</button>
</form>

{% if output %}
<pre class="bg-black text-success p-3 mt-3">{{ output }}</pre>
{% endif %}

<hr>

<h5>Users</h5>
<ul class="list-group">
{% for u in users %}
<li class="list-group-item bg-dark text-white">{{ u }}</li>
{% endfor %}
</ul>

</div>
</div>
</body>
</html>
"""

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABILITY: SQL Injection - user input directly in query (Tampering / Info Disclosure)
        conn = sqlite3.connect(DB_PATH)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            result = conn.execute(query).fetchone()
        except Exception as e:
            # VULNERABILITY: Verbose error messages expose internals (Information Disclosure)
            return f"<b>Database Error:</b> {e}<br>Query was: <code>{query}</code>", 500
        conn.close()

        if result:
            resp = redirect("/dashboard")
            resp.set_cookie("user", result[1])
            resp.set_cookie("role", result[3])
            resp.set_cookie("logged_in", "true")   # ✅ ADD THIS
            return resp
        else:
            error = "Invalid credentials"
            # VULNERABILITY: No account lockout after failed attempts (Broken Authentication)

    return render_template_string(LOGIN_PAGE, error=error)


@app.route("/dashboard")
def dashboard():
    if request.cookies.get("logged_in") != "true":
      return redirect("/")

    user = request.cookies.get("user")
    role = request.cookies.get("role")

    return render_template_string(DASHBOARD, user=user, role=role)


@app.route("/search", methods=["GET", "POST"])
def search():
    if request.cookies.get("logged_in") != "true":
      return redirect("/")
    results, error = [], None
    if request.method == "POST":
        query = request.form.get("query", "")
        conn = sqlite3.connect(DB_PATH)
        # VULNERABILITY: SQL Injection via search query (Tampering)
        sql = f"SELECT * FROM students WHERE name LIKE '%{query}%' OR roll_no LIKE '%{query}%'"
        try:
            results = conn.execute(sql).fetchall()
        except Exception as e:
            error = str(e)
        conn.close()
    return render_template_string(SEARCH_PAGE, results=results, error=error)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.cookies.get("logged_in") != "true":
      return redirect("/")
    msg = None
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            # VULNERABILITY: No file type validation - allows .php/.sh uploads (Elevation of Privilege)
            upload_dir = "uploads"
            os.makedirs(upload_dir, exist_ok=True)
            filepath = os.path.join(upload_dir, f.filename)
            # VULNERABILITY: Path traversal - filename not sanitized (Information Disclosure)
            f.save(filepath)
            msg = f"File saved to {filepath}"
    return render_template_string(UPLOAD_PAGE, msg=msg)


@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    

    if request.cookies.get("logged_in") != "true":
        return redirect("/")

    if request.cookies.get("role") != "admin":   # 🔥 ADD THIS LINE
        return "Access Denied", 403
    
    # previous
    # if "user" not in session:
    #     return redirect("/")
    # VULNERABILITY: No role check - any logged-in user can access admin (Elevation of Privilege)
    output, users = None, []
    conn = sqlite3.connect(DB_PATH)
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()

    if request.method == "POST":
        cmd = request.form.get("cmd", "")
        # VULNERABILITY: OS Command Injection (Tampering / Elevation of Privilege)
        output = subprocess.getoutput(cmd)

    return render_template_string(ADMIN_PAGE, output=output, users=users)


@app.route("/student/<int:student_id>")
def get_student(student_id):
    if request.cookies.get("logged_in") != "true":
        return redirect("/")
    # VULNERABILITY: IDOR - no ownership check; any user can view any student record
    conn = sqlite3.connect(DB_PATH)
    student = conn.execute(f"SELECT * FROM students WHERE id={student_id}").fetchone()
    conn.close()
    if student:
        return f"<pre>{student}</pre>"
    return "Not found", 404


@app.route("/api/data")
def api_data():
    # VULNERABILITY: No authentication on API endpoint (Broken Authentication)
    # VULNERABILITY: Exposes ALL student data including sensitive fields
    conn = sqlite3.connect(DB_PATH)
    data = conn.execute("SELECT * FROM students").fetchall()
    conn.close()
    return {"students": [list(r) for r in data]}


@app.route("/deserialize", methods=["POST"])
def deserialize():
    # VULNERABILITY: Insecure deserialization using pickle (Remote Code Execution)
    data = request.data
    obj = pickle.loads(data)  # noqa: S301
    return str(obj)


@app.route("/logout")
def logout():
    resp = redirect("/")
    resp.set_cookie("user", "", expires=0)
    resp.set_cookie("role", "", expires=0)
    resp.set_cookie("logged_in", "", expires=0)
    return resp


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)


if __name__ == "__main__":
    init_db()
    # VULNERABILITY: Debug mode enabled in production (Information Disclosure)
    app.run(debug=True, host="0.0.0.0", port=3000)
