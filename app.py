from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, make_response, session
)
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from pathlib import Path
import sqlite3
import csv
import io
import os
import secrets

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

app = Flask(__name__)

# Set CIVICFIX_PRODUCTION=1 on Render. Never put secret values in this file.
IS_PRODUCTION = os.environ.get("CIVICFIX_PRODUCTION") == "1"
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

if IS_PRODUCTION:
    if not FLASK_SECRET_KEY or not ADMIN_PASSWORD_HASH:
        raise RuntimeError(
            "Production requires FLASK_SECRET_KEY and ADMIN_PASSWORD_HASH."
        )
    if not DATABASE_URL:
        raise RuntimeError("Production requires the DATABASE_URL environment variable.")
    app.secret_key = FLASK_SECRET_KEY
else:
    app.secret_key = FLASK_SECRET_KEY or "civicfix-local-development-secret-key"
    if not ADMIN_PASSWORD_HASH:
        ADMIN_PASSWORD_HASH = generate_password_hash("CivicFix@123")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
)

BASE_DIR = Path(__file__).resolve().parent
SQLITE_DATABASE = os.environ.get("CIVICFIX_DATABASE", str(BASE_DIR / "civicfix.db"))
USE_POSTGRES = bool(DATABASE_URL)
VALID_STATUSES = ["Submitted", "In Progress", "Resolved"]


class DatabaseCursor:
    """Small cursor wrapper so SQLite and PostgreSQL return similar rows."""
    def __init__(self, cursor, lastrowid=None):
        self.cursor = cursor
        self.lastrowid = lastrowid

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()


class DatabaseCursor:
    def __init__(self, cursor, lastrowid=None):
        self.cursor = cursor
        self.lastrowid = lastrowid

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()


class DatabaseConnection:
    def __init__(self):
        if USE_POSTGRES:
            if psycopg is None:
                raise RuntimeError("PostgreSQL driver missing.")

            self.connection = psycopg.connect(
                DATABASE_URL,
                row_factory=dict_row
            )
            self.is_postgres = True
        else:
            self.connection = sqlite3.connect(SQLITE_DATABASE)
            self.connection.row_factory = sqlite3.Row
            self.is_postgres = False

    def execute(self, query, values=()):
        if not self.is_postgres:
            cursor = self.connection.execute(query, values)
            return DatabaseCursor(cursor, cursor.lastrowid)

        query = query.replace("?", "%s")
        cursor = self.connection.cursor()

        wants_insert_id = (
            query.lstrip().upper().startswith("INSERT INTO REPORTS")
            and "RETURNING" not in query.upper()
        )

        if wants_insert_id:
            query = query.rstrip().rstrip(";") + " RETURNING id"

        cursor.execute(query, values)

        inserted_id = None
        if wants_insert_id:
            row = cursor.fetchone()
            inserted_id = row["id"] if row else None

        return DatabaseCursor(cursor, inserted_id)

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.close()

def get_database():
    return DatabaseConnection()


def create_unique_tracking_code(connection):
    while True:
        code = "CF-" + secrets.token_hex(4).upper()
        exists = connection.execute(
            "SELECT 1 FROM reports WHERE tracking_code = ?", (code,)
        ).fetchone()
        if not exists:
            return code


def create_database():
    connection = get_database()

    if USE_POSTGRES:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                category TEXT NOT NULL,
                location TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'Submitted',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tracking_code TEXT
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS status_history (
                id BIGSERIAL PRIMARY KEY,
                report_id BIGINT NOT NULL REFERENCES reports(id),
                old_status TEXT,
                new_status TEXT NOT NULL,
                remarks TEXT,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute(
            "ALTER TABLE reports ADD COLUMN IF NOT EXISTS created_at TIMESTAMP"
        )
        connection.execute(
            "ALTER TABLE reports ADD COLUMN IF NOT EXISTS tracking_code TEXT"
        )
    else:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                category TEXT NOT NULL,
                location TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'Submitted',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                remarks TEXT,
                changed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (report_id) REFERENCES reports(id)
            )
        """)
        columns = {
            row["name"] for row in connection.execute(
                "PRAGMA table_info(reports)"
            ).fetchall()
        }
        if "created_at" not in columns:
            connection.execute("ALTER TABLE reports ADD COLUMN created_at TEXT")
        if "tracking_code" not in columns:
            connection.execute("ALTER TABLE reports ADD COLUMN tracking_code TEXT")

    connection.execute("""
        UPDATE reports
        SET created_at = CURRENT_TIMESTAMP
        WHERE created_at IS NULL
    """)

    existing = connection.execute("""
        SELECT id FROM reports
        WHERE tracking_code IS NULL OR tracking_code = ''
    """).fetchall()
    for report in existing:
        code = create_unique_tracking_code(connection)
        connection.execute(
            "UPDATE reports SET tracking_code = ? WHERE id = ?",
            (code, report["id"])
        )

    connection.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_tracking_code
        ON reports(tracking_code)
    """)

    connection.execute("""
        INSERT INTO status_history
        (report_id, old_status, new_status, remarks, changed_at)
        SELECT
            r.id,
            NULL,
            r.status,
            'Initial status',
            COALESCE(r.created_at, CURRENT_TIMESTAMP)
        FROM reports r
        WHERE NOT EXISTS (
            SELECT 1 FROM status_history h WHERE h.report_id = r.id
        )
    """)

    connection.commit()
    connection.close()


def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please login to access the admin dashboard.")
            return redirect(url_for("login"))
        return route_function(*args, **kwargs)
    return wrapper


def fetch_reports(search="", category="", status=""):
    connection = get_database()
    query = "SELECT * FROM reports WHERE 1=1"
    values = []
    if search:
        query += " AND (name LIKE ? OR location LIKE ?)"
        values.extend([f"%{search}%", f"%{search}%"])
    if category:
        query += " AND category = ?"
        values.append(category)
    if status:
        query += " AND status = ?"
        values.append(status)
    query += " ORDER BY id DESC"
    reports = connection.execute(query, values).fetchall()
    connection.close()
    return reports


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        category = request.form.get("category", "").strip()
        location = request.form.get("location", "").strip()
        description = request.form.get("description", "").strip()

        if not all([name, email, category, location, description]):
            flash("Please complete all fields.")
            return redirect(url_for("home") + "#report-preview")

        connection = get_database()
        tracking_code = create_unique_tracking_code(connection)
        cursor = connection.execute("""
            INSERT INTO reports
            (name, email, category, location, description, status, tracking_code)
            VALUES (?, ?, ?, ?, ?, 'Submitted', ?)
        """, (name, email, category, location, description, tracking_code))
        report_id = cursor.lastrowid
        connection.execute("""
            INSERT INTO status_history
            (report_id, old_status, new_status, remarks)
            VALUES (?, NULL, 'Submitted', 'Complaint submitted')
        """, (report_id,))
        connection.commit()
        connection.close()
        return render_template("success.html", tracking_code=tracking_code)
    return render_template("index.html")


@app.route("/track", methods=["GET", "POST"])
def track_complaint():
    report = None
    history = []
    searched = False
    error = None
    if request.method == "POST":
        searched = True
        tracking_code = request.form.get("tracking_code", "").strip().upper()
        email = request.form.get("email", "").strip().lower()
        if not tracking_code or not email:
            error = "Enter both your tracking ID and email address."
        else:
            connection = get_database()
            report = connection.execute("""
                SELECT tracking_code, category, location, status, created_at
                FROM reports
                WHERE tracking_code = ? AND LOWER(email) = ?
            """, (tracking_code, email)).fetchone()
            if report is not None:
                history = connection.execute("""
                    SELECT old_status, new_status, remarks, changed_at
                    FROM status_history
                    WHERE report_id = (
                        SELECT id FROM reports WHERE tracking_code = ?
                    )
                    ORDER BY id DESC
                """, (tracking_code,)).fetchall()
            connection.close()
            if report is None:
                error = (
                    "No matching complaint was found. "
                    "Check your tracking ID and email."
                )
    return render_template(
        "track.html", report=report, history=history,
        searched=searched, error=error
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if (
            username == ADMIN_USERNAME
            and check_password_hash(ADMIN_PASSWORD_HASH, password)
        ):
            session.clear()
            session["admin_logged_in"] = True
            flash("Login successful!")
            return redirect(url_for("admin"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for("login"))


@app.route("/admin")
@login_required
def admin():
    search = request.args.get("search", "").strip()
    category = request.args.get("category", "")
    status = request.args.get("status", "")
    reports = fetch_reports(search, category, status)
    connection = get_database()
    stats = connection.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'Submitted' THEN 1 ELSE 0 END) AS submitted,
            SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) AS in_progress,
            SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) AS resolved
        FROM reports
    """).fetchone()
    connection.close()
    return render_template(
        "admin.html", reports=reports,
        total=stats["total"] or 0,
        submitted=stats["submitted"] or 0,
        in_progress=stats["in_progress"] or 0,
        resolved=stats["resolved"] or 0,
        search=search, category=category, status=status
    )


@app.route("/complaint/<int:report_id>")
@login_required
def complaint_details(report_id):
    connection = get_database()
    report = connection.execute(
        "SELECT * FROM reports WHERE id = ?", (report_id,)
    ).fetchone()
    history = connection.execute("""
        SELECT * FROM status_history
        WHERE report_id = ? ORDER BY id DESC
    """, (report_id,)).fetchall()
    connection.close()
    if report is None:
        flash("Complaint not found.")
        return redirect(url_for("admin"))
    return render_template(
        "complaint_details.html", report=report, history=history
    )


@app.route("/update-status/<int:report_id>", methods=["POST"])
@login_required
def update_status(report_id):
    status = request.form.get("status", "")
    remarks = request.form.get("remarks", "").strip()
    if status not in VALID_STATUSES:
        flash("Invalid status selected.")
        return redirect(url_for("admin"))
    if len(remarks) > 500:
        flash("Remarks must be 500 characters or fewer.")
        return redirect(url_for("admin"))

    connection = get_database()
    report = connection.execute(
        "SELECT status FROM reports WHERE id = ?", (report_id,)
    ).fetchone()
    if report is None:
        connection.close()
        flash("Complaint not found.")
        return redirect(url_for("admin"))

    old_status = report["status"]
    if old_status != status:
        connection.execute(
            "UPDATE reports SET status = ? WHERE id = ?", (status, report_id)
        )
        connection.execute("""
            INSERT INTO status_history
            (report_id, old_status, new_status, remarks)
            VALUES (?, ?, ?, ?)
        """, (report_id, old_status, status, remarks or "Status updated by admin"))
    connection.commit()
    connection.close()
    flash("Complaint status updated.")
    return redirect(url_for("admin"))


@app.route("/export")
@login_required
def export_reports():
    search = request.args.get("search", "").strip()
    category = request.args.get("category", "")
    status = request.args.get("status", "")
    reports = fetch_reports(search, category, status)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Tracking ID", "Name", "Email", "Category",
        "Location", "Description", "Status", "Submitted On"
    ])
    for report in reports:
        writer.writerow([
            report["id"], report["tracking_code"], report["name"],
            report["email"], report["category"], report["location"],
            report["description"], report["status"], report["created_at"]
        ])
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = (
        "attachment; filename=civicfix_reports.csv"
    )
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response


# Initialize tables on local startup and when Render imports this module.
create_database()


if __name__ == "__main__":
    print("CivicFix database initialized.")
    print("Starting CivicFix server...")
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5001)),
        debug=False,
        use_reloader=False
    )
