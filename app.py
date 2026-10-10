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
