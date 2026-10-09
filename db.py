import os
import sqlite3
from flask import g
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "emp.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    department TEXT,
    contact TEXT
);

CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'Active'
);

CREATE TABLE IF NOT EXISTS exams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL REFERENCES courses(id),
    examiner_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    exam_type TEXT NOT NULL,
    duration INTEGER NOT NULL,
    max_marks INTEGER NOT NULL,
    slot_create_start TEXT NOT NULL,
    slot_create_end TEXT NOT NULL,
    booking_start TEXT NOT NULL,
    booking_end TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Draft'
);

CREATE TABLE IF NOT EXISTS rubrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exam_id INTEGER NOT NULL REFERENCES exams(id),
    criterion TEXT NOT NULL,
    max_marks REAL NOT NULL,
    weightage REAL NOT NULL DEFAULT 0,
    description TEXT
);

CREATE TABLE IF NOT EXISTS slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exam_id INTEGER NOT NULL REFERENCES exams(id),
    examiner_id INTEGER NOT NULL REFERENCES users(id),
    slot_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    available_seats INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'Available'
);

CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES users(id),
    slot_id INTEGER NOT NULL REFERENCES slots(id),
    booking_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Booked',
    total_marks REAL,
    remarks TEXT
);

CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id INTEGER NOT NULL REFERENCES bookings(id),
    rubric_id INTEGER NOT NULL REFERENCES rubrics(id),
    marks REAL NOT NULL
);
"""


def get_db():
    """Open one database connection per request."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    """Run a SELECT. Returns a list of rows, or one row (or None) if one=True."""
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql, args=()):
    """Run an INSERT / UPDATE / DELETE and save it."""
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


def init_db():
    """Create all tables and the admin user (only if they do not exist)."""
    db = sqlite3.connect(DATABASE)
    db.executescript(SCHEMA)
    admin = db.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
    if admin is None:
        db.execute(
            "INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, ?, ?)",
            ("Admin", "admin@emp.com", generate_password_hash("admin123"), "admin", "active"),
        )
        db.commit()
    db.close()
