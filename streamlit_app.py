
import os
import re
import csv
import io
import sqlite3
import secrets
import hashlib
import hmac
from pathlib import Path

import pandas as pd
import streamlit as st

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None


# --------------------------------------------------
# PAGE SETTINGS
# --------------------------------------------------

st.set_page_config(
    page_title="CivicFix",
    page_icon="🏛️",
    layout="wide"
)

BASE_DIR = Path(__file__).resolve().parent
SQLITE_DATABASE = BASE_DIR / "civicfix.db"


# --------------------------------------------------
# SETTINGS
# --------------------------------------------------

def get_setting(name, default=""):
    try:
        value = st.secrets.get(name, None)
        if value is not None:
            return value
    except Exception:
        pass

    return os.environ.get(name, default)


DATABASE_URL = get_setting("DATABASE_URL", "")
ADMIN_USERNAME = get_setting("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = get_setting("ADMIN_PASSWORD_HASH", "")

USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES and psycopg is None:
    st.error(
        "PostgreSQL driver is missing. "
        "Run: python -m pip install psycopg[binary]"
    )
    st.stop()


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_connection():
    if USE_POSTGRES:
        return psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row
        )

    connection = sqlite3.connect(SQLITE_DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def execute_query(sql, params=(), fetch=None):
    connection = get_connection()

    try:
        cursor = connection.cursor()

        if USE_POSTGRES:
            sql = sql.replace("?", "%s")

        cursor.execute(sql, params)

        if fetch == "one":
            result = cursor.fetchone()
        elif fetch == "all":
            result = cursor.fetchall()
        else:
            connection.commit()
            result = None

        cursor.close()
        return result

    finally:
        connection.close()


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def initialize_database():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        if USE_POSTGRES:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    category TEXT NOT NULL,
                    location TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT DEFAULT 'Submitted',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    tracking_code TEXT UNIQUE
                )
            """)

            cursor.execute("""
                ALTER TABLE reports
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
            """)

            cursor.execute("""
                ALTER TABLE reports
                ADD COLUMN IF NOT EXISTS tracking_code TEXT
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS status_history (
                    id BIGSERIAL PRIMARY KEY,
                    report_id BIGINT REFERENCES reports(id)
                    ON DELETE CASCADE,
                    old_status TEXT,
                    new_status TEXT NOT NULL,
                    remarks TEXT,
                    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    category TEXT NOT NULL,
                    location TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT DEFAULT 'Submitted',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    tracking_code TEXT UNIQUE
                )
            """)

            cursor.execute("PRAGMA table_info(reports)")
            columns = [row["name"] for row in cursor.fetchall()]

            if "created_at" not in columns:
                cursor.execute("""
                    ALTER TABLE reports
                    ADD COLUMN created_at TEXT
                """)

            if "tracking_code" not in columns:
                cursor.execute("""
                    ALTER TABLE reports
                    ADD COLUMN tracking_code TEXT
                """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER,
                    old_status TEXT,
                    new_status TEXT NOT NULL,
                    remarks TEXT,
                    changed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(report_id) REFERENCES reports(id)
                    ON DELETE CASCADE
                )
            """)

        cursor.execute("SELECT id, tracking_code, status FROM reports")
        reports = cursor.fetchall()

        for report in reports:
            tracking_code = report["tracking_code"]

            if not tracking_code:
                tracking_code = "CF-" + secrets.token_hex(4).upper()

                cursor.execute("""
                    UPDATE reports
                    SET tracking_code = ?
                    WHERE id = ?
                """, (tracking_code, report["id"]))

            cursor.execute("""
                SELECT id FROM status_history
                WHERE report_id = ?
            """, (report["id"],))

            if cursor.fetchone() is None:
                cursor.execute("""
                    INSERT INTO status_history
                    (report_id, old_status, new_status, remarks)
                    VALUES (?, ?, ?, ?)
                """, (
                    report["id"],
                    None,
                    report["status"] or "Submitted",
                    "Initial complaint status"
                ))

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_reports_tracking_code
            ON reports(tracking_code)
        """)

        connection.commit()
        cursor.close()

    finally:
        connection.close()


initialize_database()


# --------------------------------------------------
# PASSWORD VERIFICATION
# Supports PBKDF2 and scrypt hashes
# --------------------------------------------------

def verify_password(password, stored_hash):

    # Security: never allow a default password.
    # Admin login fails if no password hash is configured.
    if not stored_hash:
        return False

    try:
        method, salt, expected_hash = stored_hash.split("$")

        if method.startswith("pbkdf2:"):
            parts = method.split(":")
            algorithm = parts[1]
            iterations = int(parts[2]) if len(parts) > 2 else 600000

            actual_hash = hashlib.pbkdf2_hmac(
                algorithm,
                password.encode(),
                salt.encode(),
                iterations
            ).hex()

        elif method.startswith("scrypt:"):
            parts = method.split(":")
            n = int(parts[1])
            r = int(parts[2])
            p = int(parts[3])

            actual_hash = hashlib.scrypt(
                password.encode(),
                salt=salt.encode(),
                n=n,
                r=r,
                p=p,
                dklen=len(bytes.fromhex(expected_hash))
            ).hex()

        else:
            return False

        return hmac.compare_digest(
            actual_hash,
            expected_hash
        )

    except Exception:
        return False


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def create_tracking_code():
    return "CF-" + secrets.token_hex(4).upper()


def get_report_by_id(report_id):
    return execute_query(
        "SELECT * FROM reports WHERE id = ?",
        (report_id,),
        fetch="one"
    )


def get_status_history(report_id):
    return execute_query("""
        SELECT * FROM status_history
        WHERE report_id = ?
        ORDER BY changed_at ASC, id ASC
    """, (report_id,), fetch="all")


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

if "admin_logged_in" not in st.session_state:
    st.session_state.admin_logged_in = False


# --------------------------------------------------
# SIDEBAR NAVIGATION
# --------------------------------------------------

st.sidebar.title("🏛️ CivicFix")
st.sidebar.caption("Citizen Complaint Management System")

pages = [
    "Home",
    "Track Complaint",
    "Admin Login"
]

if st.session_state.admin_logged_in:
    pages.append("Admin Dashboard")

page = st.sidebar.radio("Navigation", pages)

st.sidebar.divider()
st.sidebar.info(
    "CivicFix helps citizens submit complaints "
    "and track their resolution."
)


# --------------------------------------------------
# HOME PAGE - COMPLAINT SUBMISSION
# --------------------------------------------------

if page == "Home":

    st.title("🏛️ CivicFix")
    st.subheader("Citizen Complaint Registration")

    st.write(
        "Report civic issues in your area and track "
        "their progress using your tracking ID."
    )

    with st.form("complaint_form"):

        name = st.text_input("Full Name")
        email = st.text_input("Email Address")

        category = st.selectbox(
            "Complaint Category",
            [
                "Road and Infrastructure",
                "Water Supply",
                "Electricity",
                "Sanitation",
                "Garbage Collection",
                "Street Lights",
                "Drainage",
                "Public Safety",
                "Other"
            ]
        )

        location = st.text_input("Complaint Location")

        description = st.text_area(
            "Complaint Description",
            height=150
        )

        submitted = st.form_submit_button(
            "Submit Complaint",
            use_container_width=True
        )

        if submitted:

            if not all([
                name.strip(),
                email.strip(),
                location.strip(),
                description.strip()
            ]):
                st.error("Please fill in all required fields.")

            elif not re.match(
                r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
                email.strip()
            ):
                st.error("Please enter a valid email address.")

            else:

                tracking_code = create_tracking_code()

                try:
                    execute_query("""
                        INSERT INTO reports
                        (
                            name,
                            email,
                            category,
                            location,
                            description,
                            status,
                            tracking_code
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        name.strip(),
                        email.strip(),
                        category,
                        location.strip(),
                        description.strip(),
                        "Submitted",
                        tracking_code
                    ))

                    report = execute_query("""
                        SELECT id FROM reports
                        WHERE tracking_code = ?
                    """, (tracking_code,), fetch="one")

                    execute_query("""
                        INSERT INTO status_history
                        (report_id, old_status, new_status, remarks)
                        VALUES (?, ?, ?, ?)
                    """, (
                        report["id"],
                        None,
                        "Submitted",
                        "Complaint successfully submitted"
                    ))

                    st.success("Complaint submitted successfully!")

                    st.subheader("Your Tracking ID")
                    st.code(tracking_code)

                    st.info(
                        "Save this tracking ID. You will need it "
                        "and your email address to track your complaint."
                    )

                except Exception as error:
                    st.error(f"Could not submit complaint: {error}")


# --------------------------------------------------
# TRACK COMPLAINT PAGE
# --------------------------------------------------

elif page == "Track Complaint":

    st.title("🔎 Track Your Complaint")

    st.write(
        "Enter your tracking ID and the same email address "
        "you used when submitting the complaint."
    )

    with st.form("tracking_form"):

        tracking_code = st.text_input(
            "Tracking ID",
            placeholder="Example: CF-A1B2C3D4"
        )

        tracking_email = st.text_input("Email Address")

        track_button = st.form_submit_button(
            "Track Complaint",
            use_container_width=True
        )

    if track_button:

        if not tracking_code.strip() or not tracking_email.strip():
            st.error("Enter both tracking ID and email address.")

        else:

            report = execute_query("""
                SELECT * FROM reports
                WHERE tracking_code = ?
                AND LOWER(email) = LOWER(?)
            """, (
                tracking_code.strip().upper(),
                tracking_email.strip()
            ), fetch="one")

            if report is None:
                st.error(
                    "No matching complaint found. "
                    "Check your tracking ID and email address."
                )

            else:

                st.success("Complaint found!")

                col1, col2 = st.columns(2)

                col1.metric("Tracking ID", report["tracking_code"])
                col2.metric("Current Status", report["status"])

                st.subheader("Complaint Details")

                st.write("**Name:**", report["name"])
                st.write("**Category:**", report["category"])
                st.write("**Location:**", report["location"])
                st.write("**Description:**", report["description"])
                st.write("**Submitted On:**", report["created_at"])

                st.subheader("Complaint Progress")

                history = get_status_history(report["id"])

                if history:
                    for item in history:
                        st.markdown(
                            f"**{item['new_status']}**  \n"
                            f"{item['remarks'] or 'Status updated'}  \n"
                            f"<small>{item['changed_at']}</small>",
                            unsafe_allow_html=True
                        )
                        st.divider()

                else:
                    st.info("No progress updates are available yet.")


# --------------------------------------------------
# ADMIN LOGIN
# --------------------------------------------------

elif page == "Admin Login":

    st.title("🔐 Admin Login")

    if st.session_state.admin_logged_in:

        st.success("You are already logged in as admin.")

        if st.button("Logout"):
            st.session_state.admin_logged_in = False
            st.rerun()

    else:

        with st.form("admin_login_form"):

            username = st.text_input("Admin Username")
            password = st.text_input(
                "Admin Password",
                type="password"
            )

            login_button = st.form_submit_button(
                "Login",
                use_container_width=True
            )

        if login_button:

            if (
                username == ADMIN_USERNAME
                and verify_password(password, ADMIN_PASSWORD_HASH)
            ):
                st.session_state.admin_logged_in = True
                st.success("Login successful!")
                st.rerun()

            else:
                st.error("Invalid username or password.")


# --------------------------------------------------
# ADMIN DASHBOARD
# --------------------------------------------------

elif page == "Admin Dashboard":

    if not st.session_state.admin_logged_in:
        st.error("Please log in as admin first.")
        st.stop()

    st.title("📊 Admin Dashboard")

    if st.button("Logout"):
        st.session_state.admin_logged_in = False
        st.rerun()

    reports = execute_query("""
        SELECT * FROM reports
        ORDER BY id DESC
    """, fetch="all")

    total = len(reports)
    submitted_count = sum(
        1 for report in reports
        if report["status"] == "Submitted"
    )
    progress_count = sum(
        1 for report in reports
        if report["status"] == "In Progress"
    )
    resolved_count = sum(
        1 for report in reports
        if report["status"] == "Resolved"
    )

    st.subheader("Complaint Statistics")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Complaints", total)
    col2.metric("Submitted", submitted_count)
    col3.metric("In Progress", progress_count)
    col4.metric("Resolved", resolved_count)

    st.divider()

    st.subheader("Complaint Management")

    search_text = st.text_input(
        "Search by name, location or tracking ID"
    )

    filter_status = st.selectbox(
        "Filter by Status",
        [
            "All",
            "Submitted",
            "In Progress",
            "Resolved"
        ]
    )

    filter_category = st.selectbox(
        "Filter by Category",
        ["All"] + sorted(
            list(set(report["category"] for report in reports))
        )
    )

    filtered_reports = []

    for report in reports:

        searchable = (
            str(report["name"]) + " " +
            str(report["location"]) + " " +
            str(report["tracking_code"])
        ).lower()

        if search_text.lower() not in searchable:
            continue

        if (
            filter_status != "All"
            and report["status"] != filter_status
        ):
            continue

        if (
            filter_category != "All"
            and report["category"] != filter_category
        ):
            continue

        filtered_reports.append(report)

    if filtered_reports:

        table_data = []

        for report in filtered_reports:
            table_data.append({
                "ID": report["id"],
                "Tracking ID": report["tracking_code"],
                "Name": report["name"],
                "Category": report["category"],
                "Location": report["location"],
                "Status": report["status"],
                "Submitted On": str(report["created_at"])
            })

        st.dataframe(
            pd.DataFrame(table_data),
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No complaints match your search or filters.")

    st.divider()

    st.subheader("Update Complaint Status")

    if reports:

        report_options = {
            f"{report['tracking_code']} - {report['name']}": report["id"]
            for report in reports
        }

        selected_label = st.selectbox(
            "Select Complaint",
            list(report_options.keys())
        )

        selected_id = report_options[selected_label]
        selected_report = get_report_by_id(selected_id)

        st.write("**Current Status:**", selected_report["status"])
        st.write("**Description:**", selected_report["description"])

        with st.form("update_status_form"):

            new_status = st.selectbox(
                "New Status",
                ["Submitted", "In Progress", "Resolved"],
                index=[
                    "Submitted",
                    "In Progress",
                    "Resolved"
                ].index(selected_report["status"])
                if selected_report["status"] in [
                    "Submitted",
                    "In Progress",
                    "Resolved"
                ] else 0
            )

            remarks = st.text_area("Admin Remarks")

            update_button = st.form_submit_button(
                "Update Status",
                use_container_width=True
            )

            if update_button:

                if not remarks.strip():
                    st.error("Please enter remarks for this update.")

                else:

                    execute_query("""
                        UPDATE reports
                        SET status = ?
                        WHERE id = ?
                    """, (new_status, selected_id))

                    execute_query("""
                        INSERT INTO status_history
                        (
                            report_id,
                            old_status,
                            new_status,
                            remarks
                        )
                        VALUES (?, ?, ?, ?)
                    """, (
                        selected_id,
                        selected_report["status"],
                        new_status,
                        remarks.strip()
                    ))

                    st.success("Complaint status updated successfully!")
                    st.rerun()

    else:
        st.info("There are no complaints to update yet.")

    st.divider()

    st.subheader("Export Complaints")

    if reports:

        csv_data = []

        for report in reports:
            csv_data.append({
                "ID": report["id"],
                "Tracking ID": report["tracking_code"],
                "Name": report["name"],
                "Email": report["email"],
                "Category": report["category"],
                "Location": report["location"],
                "Description": report["description"],
                "Status": report["status"],
                "Submitted On": str(report["created_at"])
            })

        csv_buffer = io.StringIO()
        writer = csv.DictWriter(
            csv_buffer,
            fieldnames=csv_data[0].keys()
        )

        writer.writeheader()
        writer.writerows(csv_data)

        st.download_button(
            "⬇️ Export Complaints as CSV",
            data=csv_buffer.getvalue(),
            file_name="civicfix_complaints.csv",
            mime="text/csv",
            use_container_width=True
        )

    else:
        st.info("No complaint records are available to export.")
