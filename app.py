from datetime import date, datetime
from functools import wraps
from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from db import close_db, execute, get_db, init_db, query

app = Flask(__name__)
app.config["SECRET_KEY"] = "emp-secret-key-change-me"
app.teardown_appcontext(close_db)

init_db()  # creates the database file, the tables and the admin user

EXAM_TYPES = ["Viva", "Practical", "Project Demo", "Assessment"]
EXAM_STATUSES = ["Draft", "Slot Creation", "Booking Open", "Closed", "Completed"]


# ---------------------------------------------------------------- helpers
def today():
    return date.today().isoformat()  # e.g. 2026-10-09


def valid_date(text):
    try:
        datetime.strptime(text, "%Y-%m-%d")
        return True
    except (ValueError, TypeError):
        return False


def valid_time(text):
    try:
        datetime.strptime(text, "%H:%M")
        return True
    except (ValueError, TypeError):
        return False


def to_int(text):
    try:
        return int(text)
    except (ValueError, TypeError):
        return None


def to_float(text):
    try:
        return float(text)
    except (ValueError, TypeError):
        return None


def count(sql, args=()):
    return query(sql, args, one=True)[0]


def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)


@app.context_processor
def inject_user():
    # makes `current_user` available in every template
    return {"current_user": current_user()}


def login_required(role):
    """Only allow users with the given role to open a page."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            if user["status"] != "active":
                session.clear()
                flash("Your account is not active.", "danger")
                return redirect(url_for("login"))
            if user["role"] != role:
                flash("You are not allowed to open that page.", "danger")
                return redirect("/" + user["role"])
            return func(*args, **kwargs)
        return wrapper
    return decorator


def booking_rows(where="", args=()):
    """One query that returns bookings together with exam, slot and user details."""
    sql = """
    SELECT b.*, s.slot_date, s.start_time, s.end_time,
           e.id AS exam_id, e.name AS exam_name, e.status AS exam_status,
           e.booking_end, e.max_marks,
           c.name AS course_name,
           u.name AS student_name, x.name AS examiner_name
    FROM bookings b
    JOIN slots s ON s.id = b.slot_id
    JOIN exams e ON e.id = s.exam_id
    JOIN courses c ON c.id = e.course_id
    JOIN users u ON u.id = b.student_id
    JOIN users x ON x.id = s.examiner_id
    """
    return query(sql + " " + where + " ORDER BY b.id DESC", args)


# ------------------------------------------------------ login / register
@app.route("/")
def home():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    return redirect("/" + user["role"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        department = request.form.get("department", "").strip()
        contact = request.form.get("contact", "").strip()

        if not name or not email or not password:
            flash("Name, email and password are required.", "danger")
        elif role not in ("student", "examiner"):
            flash("Please choose Student or Examiner.", "danger")
        elif len(password) < 6:
            flash("Password must have at least 6 characters.", "danger")
        elif query("SELECT id FROM users WHERE email = ?", (email,), one=True):
            flash("That email is already registered.", "danger")
        else:
            status = "pending" if role == "examiner" else "active"
            execute(
                "INSERT INTO users (name, email, password, role, status, department, contact) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, email, generate_password_hash(password), role, status, department, contact),
            )
            if role == "examiner":
                flash("Registered. You can log in after the admin approves you.", "info")
            else:
                flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if user is None or not check_password_hash(user["password"], password):
            flash("Wrong email or password.", "danger")
        elif user["status"] == "pending":
            flash("Your account is waiting for admin approval.", "warning")
        elif user["status"] == "deactivated":
            flash("Your account has been deactivated.", "danger")
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect("/" + user["role"])
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))
