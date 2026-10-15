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


# -------------------------------------------------------------- dashboards
@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    stats = {
        "Courses": count("SELECT COUNT(*) FROM courses"),
        "Examinations": count("SELECT COUNT(*) FROM exams"),
        "Examiners": count("SELECT COUNT(*) FROM users WHERE role = 'examiner'"),
        "Students": count("SELECT COUNT(*) FROM users WHERE role = 'student'"),
        "Examination slots": count("SELECT COUNT(*) FROM slots"),
        "Bookings": count("SELECT COUNT(*) FROM bookings"),
    }
    return render_template("admin_dashboard.html", stats=stats)


@app.route("/examiner")
@login_required("examiner")
def examiner_dashboard():
    user = current_user()
    exams = query(
        "SELECT e.*, c.name AS course_name FROM exams e "
        "JOIN courses c ON c.id = e.course_id WHERE e.examiner_id = ?",
        (user["id"],),
    )
    slot_count = count("SELECT COUNT(*) FROM slots WHERE examiner_id = ?", (user["id"],))
    booked_count = count(
        "SELECT COUNT(*) FROM bookings b JOIN slots s ON s.id = b.slot_id "
        "WHERE s.examiner_id = ? AND b.status IN ('Booked', 'Completed')",
        (user["id"],),
    )
    pending_count = count(
        "SELECT COUNT(*) FROM bookings b JOIN slots s ON s.id = b.slot_id "
        "WHERE s.examiner_id = ? AND b.status = 'Booked'",
        (user["id"],),
    )
    return render_template("examiner_dashboard.html", exams=exams, slot_count=slot_count,
                           booked_count=booked_count, pending_count=pending_count)


@app.route("/student")
@login_required("student")
def student_dashboard():
    user = current_user()
    available_exams = query(
        "SELECT e.*, c.name AS course_name FROM exams e "
        "JOIN courses c ON c.id = e.course_id WHERE e.status = 'Booking Open'"
    )
    available_slots = query(
        "SELECT s.*, e.name AS exam_name FROM slots s JOIN exams e ON e.id = s.exam_id "
        "WHERE e.status = 'Booking Open' AND s.available_seats > 0 "
        "ORDER BY s.slot_date, s.start_time"
    )
    mine = booking_rows("WHERE b.student_id = ?", (user["id"],))
    booked = [b for b in mine if b["status"] == "Booked"]
    upcoming = [b for b in booked if b["slot_date"] >= today()]
    results = [b for b in mine if b["status"] == "Completed" and b["exam_status"] == "Completed"]
    return render_template("student_dashboard.html", available_exams=available_exams,
                           available_slots=available_slots, booked=booked,
                           upcoming=upcoming, results=results)


# ------------------------------------------------------------ admin: courses
@app.route("/admin/courses")
@login_required("admin")
def admin_courses():
    courses = query("SELECT * FROM courses ORDER BY code")
    return render_template("admin_courses.html", courses=courses)


@app.route("/admin/courses/new", methods=["GET", "POST"])
@app.route("/admin/courses/<int:course_id>/edit", methods=["GET", "POST"])
@login_required("admin")
def admin_course_form(course_id=None):
    course = None
    if course_id is not None:
        course = query("SELECT * FROM courses WHERE id = ?", (course_id,), one=True)
        if course is None:
            abort(404)
    values = dict(course) if course else {}
    if request.method == "POST":
        values = request.form
        code = request.form.get("code", "").strip()
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        status = request.form.get("status", "Active")
        same_code = query("SELECT id FROM courses WHERE code = ? AND id != ?",
                          (code, course_id or 0), one=True)
        if not code or not name:
            flash("Course code and name are required.", "danger")
        elif status not in ("Active", "Inactive"):
            flash("Invalid status.", "danger")
        elif same_code:
            flash("Another course already uses that code.", "danger")
        else:
            if course is None:
                execute("INSERT INTO courses (code, name, description, status) VALUES (?, ?, ?, ?)",
                        (code, name, description, status))
                flash("Course added.", "success")
            else:
                execute("UPDATE courses SET code = ?, name = ?, description = ?, status = ? WHERE id = ?",
                        (code, name, description, status, course_id))
                flash("Course updated.", "success")
            return redirect(url_for("admin_courses"))
    return render_template("admin_course_form.html", course=course, values=values)


@app.route("/admin/courses/<int:course_id>/delete", methods=["POST"])
@login_required("admin")
def admin_course_delete(course_id):
    if count("SELECT COUNT(*) FROM exams WHERE course_id = ?", (course_id,)) > 0:
        flash("This course has examinations, so it cannot be deleted. Mark it Inactive instead.", "danger")
    else:
        execute("DELETE FROM courses WHERE id = ?", (course_id,))
        flash("Course deleted.", "success")
    return redirect(url_for("admin_courses"))


# --------------------------------------------------------- admin: examiners
@app.route("/admin/examiners")
@login_required("admin")
def admin_examiners():
    examiners = query("SELECT * FROM users WHERE role = 'examiner' ORDER BY status, name")
    return render_template("admin_examiners.html", examiners=examiners)


@app.route("/admin/examiners/<int:user_id>/<action>", methods=["POST"])
@login_required("admin")
def admin_examiner_action(user_id, action):
    examiner = query("SELECT * FROM users WHERE id = ? AND role = 'examiner'", (user_id,), one=True)
    if examiner is None or action not in ("approve", "deactivate"):
        abort(404)
    new_status = "active" if action == "approve" else "deactivated"
    execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    flash("Examiner %s is now %s." % (examiner["name"], new_status), "success")
    return redirect(url_for("admin_examiners"))


# ------------------------------------------------------------- admin: exams
@app.route("/admin/exams")
@login_required("admin")
def admin_exams():
    exams = query(
        "SELECT e.*, c.name AS course_name, u.name AS examiner_name FROM exams e "
        "JOIN courses c ON c.id = e.course_id JOIN users u ON u.id = e.examiner_id "
        "ORDER BY e.id DESC"
    )
    return render_template("admin_exams.html", exams=exams, statuses=EXAM_STATUSES)


@app.route("/admin/exams/new", methods=["GET", "POST"])
@app.route("/admin/exams/<int:exam_id>/edit", methods=["GET", "POST"])
@login_required("admin")
def admin_exam_form(exam_id=None):
    exam = None
    if exam_id is not None:
        exam = query("SELECT * FROM exams WHERE id = ?", (exam_id,), one=True)
        if exam is None:
            abort(404)
    values = dict(exam) if exam else {}
    courses = query("SELECT * FROM courses WHERE status = 'Active' ORDER BY name")
    examiners = query("SELECT * FROM users WHERE role = 'examiner' AND status = 'active' ORDER BY name")
    if request.method == "POST":
        values = request.form
        f = {k: request.form.get(k, "").strip() for k in (
            "course_id", "examiner_id", "name", "exam_type", "duration", "max_marks",
            "slot_create_start", "slot_create_end", "booking_start", "booking_end")}
        error = None
        if not f["name"]:
            error = "Examination name is required."
        elif not query("SELECT id FROM courses WHERE id = ?", (to_int(f["course_id"]),), one=True):
            error = "Please choose a course."
        elif not query("SELECT id FROM users WHERE id = ? AND role = 'examiner' AND status = 'active'",
                       (to_int(f["examiner_id"]),), one=True):
            error = "Please choose an approved examiner."
        elif f["exam_type"] not in EXAM_TYPES:
            error = "Please choose an examination type."
        elif (to_int(f["duration"]) or 0) < 1 or (to_int(f["max_marks"]) or 0) < 1:
            error = "Duration and maximum marks must be positive numbers."
        elif not all(valid_date(f[k]) for k in ("slot_create_start", "slot_create_end",
                                                "booking_start", "booking_end")):
            error = "Please fill all four dates."
        elif f["slot_create_start"] > f["slot_create_end"]:
            error = "Slot creation end date cannot be before its start date."
        elif f["booking_start"] > f["booking_end"]:
            error = "Booking end date cannot be before its start date."
        if error:
            flash(error, "danger")
        else:
            data = (int(f["course_id"]), int(f["examiner_id"]), f["name"], f["exam_type"],
                    int(f["duration"]), int(f["max_marks"]), f["slot_create_start"],
                    f["slot_create_end"], f["booking_start"], f["booking_end"])
            if exam is None:
                execute("INSERT INTO exams (course_id, examiner_id, name, exam_type, duration, "
                        "max_marks, slot_create_start, slot_create_end, booking_start, booking_end) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", data)
                flash("Examination created (status: Draft).", "success")
            else:
                db = get_db()
                db.execute("UPDATE exams SET course_id = ?, examiner_id = ?, name = ?, exam_type = ?, "
                           "duration = ?, max_marks = ?, slot_create_start = ?, slot_create_end = ?, "
                           "booking_start = ?, booking_end = ? WHERE id = ?", data + (exam_id,))
                # if the examiner changed, move the existing slots to the new examiner too
                db.execute("UPDATE slots SET examiner_id = ? WHERE exam_id = ?", (int(f["examiner_id"]),
                                                                                   exam_id))
                db.commit()
                flash("Examination updated.", "success")
            return redirect(url_for("admin_exams"))
    return render_template("admin_exam_form.html", exam=exam, values=values, courses=courses,
                           examiners=examiners, exam_types=EXAM_TYPES)


@app.route("/admin/exams/<int:exam_id>/status", methods=["POST"])
@login_required("admin")
def admin_exam_status(exam_id):
    status = request.form.get("status", "")
    if status not in EXAM_STATUSES:
        flash("Invalid status.", "danger")
    else:
        execute("UPDATE exams SET status = ? WHERE id = ?", (status, exam_id))
        flash("Status changed to " + status + ".", "success")
    return redirect(url_for("admin_exams"))


@app.route("/admin/exams/<int:exam_id>/delete", methods=["POST"])
@login_required("admin")
def admin_exam_delete(exam_id):
    if count("SELECT COUNT(*) FROM slots WHERE exam_id = ?", (exam_id,)) > 0:
        flash("This examination already has slots, so it cannot be deleted.", "danger")
    else:
        db = get_db()
        db.execute("DELETE FROM rubrics WHERE exam_id = ?", (exam_id,))
        db.execute("DELETE FROM exams WHERE id = ?", (exam_id,))
        db.commit()
        flash("Examination deleted.", "success")
    return redirect(url_for("admin_exams"))


# ----------------------------------------------------------- admin: rubrics
def rubric_error(exam, criterion, max_marks, weightage, ignore_id=0):
    if not criterion:
        return "Criterion name is required."
    if max_marks is None or max_marks <= 0:
        return "Maximum marks must be a positive number."
    if weightage is None or weightage < 0 or weightage > 100:
        return "Weightage must be between 0 and 100."
    used = query("SELECT COALESCE(SUM(max_marks), 0) FROM rubrics WHERE exam_id = ? AND id != ?",
                 (exam["id"], ignore_id), one=True)[0]
    if used + max_marks > exam["max_marks"]:
        return "Rubric marks would add up to more than the examination maximum (%s)." % exam["max_marks"]
    return None


@app.route("/admin/exams/<int:exam_id>/rubrics", methods=["GET", "POST"])
@login_required("admin")
def admin_rubrics(exam_id):
    exam = query("SELECT * FROM exams WHERE id = ?", (exam_id,), one=True)
    if exam is None:
        abort(404)
    if request.method == "POST":
        criterion = request.form.get("criterion", "").strip()
        max_marks = to_float(request.form.get("max_marks"))
        weightage = to_float(request.form.get("weightage") or "0")
        description = request.form.get("description", "").strip()
        error = rubric_error(exam, criterion, max_marks, weightage)
        if error:
            flash(error, "danger")
        else:
            execute("INSERT INTO rubrics (exam_id, criterion, max_marks, weightage, description) "
                    "VALUES (?, ?, ?, ?, ?)", (exam_id, criterion, max_marks, weightage, description))
            flash("Rubric criterion added.", "success")
            return redirect(url_for("admin_rubrics", exam_id=exam_id))
    rubrics = query("SELECT * FROM rubrics WHERE exam_id = ? ORDER BY id", (exam_id,))
    total = sum(r["max_marks"] for r in rubrics)
    return render_template("admin_rubrics.html", exam=exam, rubrics=rubrics, total=total)


@app.route("/admin/rubrics/<int:rubric_id>/edit", methods=["GET", "POST"])
@login_required("admin")
def admin_rubric_edit(rubric_id):
    rubric = query("SELECT * FROM rubrics WHERE id = ?", (rubric_id,), one=True)
    if rubric is None:
        abort(404)
    exam = query("SELECT * FROM exams WHERE id = ?", (rubric["exam_id"],), one=True)
    values = dict(rubric)
    if request.method == "POST":
        values = request.form
        criterion = request.form.get("criterion", "").strip()
        max_marks = to_float(request.form.get("max_marks"))
        weightage = to_float(request.form.get("weightage") or "0")
        description = request.form.get("description", "").strip()
        error = rubric_error(exam, criterion, max_marks, weightage, rubric_id)
        if error:
            flash(error, "danger")
        else:
            execute("UPDATE rubrics SET criterion = ?, max_marks = ?, weightage = ?, description = ? "
                    "WHERE id = ?", (criterion, max_marks, weightage, description, rubric_id))
            flash("Rubric criterion updated.", "success")
            return redirect(url_for("admin_rubrics", exam_id=exam["id"]))
    return render_template("admin_rubric_edit.html", exam=exam, rubric=rubric, values=values)


@app.route("/admin/rubrics/<int:rubric_id>/delete", methods=["POST"])
@login_required("admin")
def admin_rubric_delete(rubric_id):
    rubric = query("SELECT * FROM rubrics WHERE id = ?", (rubric_id,), one=True)
    if rubric is None:
        abort(404)
    if count("SELECT COUNT(*) FROM scores WHERE rubric_id = ?", (rubric_id,)) > 0:
        flash("This criterion has already been used for marking, so it cannot be deleted.", "danger")
    else:
        execute("DELETE FROM rubrics WHERE id = ?", (rubric_id,))
        flash("Criterion deleted.", "success")
    return redirect(url_for("admin_rubrics", exam_id=rubric["exam_id"]))


# ------------------------------------------- admin: view, search, reschedule
@app.route("/admin/students")
@login_required("admin")
def admin_students():
    students = query("SELECT * FROM users WHERE role = 'student' ORDER BY name")
    return render_template("admin_students.html", students=students)


@app.route("/admin/slots")
@login_required("admin")
def admin_slots():
    slots = query(
        "SELECT s.*, e.name AS exam_name, u.name AS examiner_name FROM slots s "
        "JOIN exams e ON e.id = s.exam_id JOIN users u ON u.id = s.examiner_id "
        "ORDER BY s.slot_date, s.start_time"
    )
    return render_template("admin_slots.html", slots=slots)


# ------------------------------------------- admin: bookings, search, reschedule
@app.route("/admin/bookings")
@login_required("admin")
def admin_bookings():
    return render_template("admin_bookings.html", bookings=booking_rows())


@app.route("/admin/search")
@login_required("admin")
def admin_search():
    q = request.args.get("q", "").strip()
    students = examiners = exams = bookings = []
    if q:
        like = "%" + q + "%"
        students = query("SELECT * FROM users WHERE role = 'student' AND "
                         "(name LIKE ? OR CAST(id AS TEXT) = ?)", (like, q))
        examiners = query("SELECT * FROM users WHERE role = 'examiner' AND "
                          "(name LIKE ? OR CAST(id AS TEXT) = ?)", (like, q))
        exams = query("SELECT e.*, c.name AS course_name FROM exams e "
                      "JOIN courses c ON c.id = e.course_id "
                      "WHERE e.name LIKE ? OR CAST(e.id AS TEXT) = ?", (like, q))
        bookings = booking_rows("WHERE u.name LIKE ? OR e.name LIKE ? OR CAST(b.id AS TEXT) = ?",
                                (like, like, q))
    return render_template("admin_search.html", q=q, students=students, examiners=examiners,
                           exams=exams, bookings=bookings)


@app.route("/admin/bookings/<int:booking_id>/reschedule", methods=["GET", "POST"])
@login_required("admin")
def admin_reschedule(booking_id):
    rows = booking_rows("WHERE b.id = ?", (booking_id,))
    if not rows:
        abort(404)
    booking = rows[0]
    if booking["status"] != "Booked":
        flash("Only bookings with status Booked can be rescheduled.", "danger")
        return redirect(url_for("admin_bookings"))
    slots = query("SELECT * FROM slots WHERE exam_id = ? AND id != ? AND available_seats > 0 "
                  "ORDER BY slot_date, start_time", (booking["exam_id"], booking["slot_id"]))
    if request.method == "POST":
        new_slot_id = to_int(request.form.get("new_slot_id"))
        if new_slot_id not in [s["id"] for s in slots]:
            flash("Please choose one of the available slots.", "danger")
        else:
            db = get_db()
            db.execute("UPDATE slots SET available_seats = available_seats + 1, status = 'Available' "
                       "WHERE id = ?", (booking["slot_id"],))
            db.execute("UPDATE slots SET available_seats = available_seats - 1, "
                       "status = CASE WHEN available_seats - 1 <= 0 THEN 'Full' ELSE 'Available' END "
                       "WHERE id = ?", (new_slot_id,))
            db.execute("UPDATE bookings SET slot_id = ? WHERE id = ?", (new_slot_id, booking_id))
            db.commit()
            flash("Booking rescheduled.", "success")
            return redirect(url_for("admin_bookings"))
    return render_template("admin_reschedule.html", booking=booking, slots=slots)


# ------------------------------------------------------------ examiner pages
def own_exam(exam_id, examiner_id):
    exam = query(
        "SELECT e.*, c.name AS course_name FROM exams e JOIN courses c ON c.id = e.course_id "
        "WHERE e.id = ? AND e.examiner_id = ?", (exam_id, examiner_id), one=True)
    if exam is None:
        abort(404)
    return exam


def own_slot(slot_id, examiner_id):
    slot = query(
        "SELECT s.*, e.status AS exam_status, e.name AS exam_name FROM slots s "
        "JOIN exams e ON e.id = s.exam_id WHERE s.id = ? AND s.examiner_id = ?",
        (slot_id, examiner_id), one=True)
    if slot is None:
        abort(404)
    return slot


@app.route("/examiner/exams")
@login_required("examiner")
def examiner_exams():
    user = current_user()
    exams = query(
        "SELECT e.*, c.name AS course_name FROM exams e JOIN courses c ON c.id = e.course_id "
        "WHERE e.examiner_id = ? ORDER BY e.id DESC", (user["id"],))
    return render_template("examiner_exams.html", exams=exams)


@app.route("/examiner/exams/<int:exam_id>/slots", methods=["GET", "POST"])
@login_required("examiner")
def examiner_slots(exam_id):
    user = current_user()
    exam = own_exam(exam_id, user["id"])
    if request.method == "POST":
        slot_date = request.form.get("slot_date", "")
        start_time = request.form.get("start_time", "")
        end_time = request.form.get("end_time", "")
        capacity = to_int(request.form.get("capacity"))
        error = None
        if exam["status"] != "Slot Creation":
            error = "Slot creation is not open for this examination."
        elif not (exam["slot_create_start"] <= today() <= exam["slot_create_end"]):
            error = "Today is outside the slot creation period."
        elif not valid_date(slot_date) or not valid_time(start_time) or not valid_time(end_time):
            error = "Please enter a valid date, start time and end time."
        elif start_time >= end_time:
            error = "End time must be after start time."
        elif capacity is None or capacity < 1:
            error = "Capacity must be at least 1."
        if error:
            flash(error, "danger")
        else:
            execute("INSERT INTO slots (exam_id, examiner_id, slot_date, start_time, end_time, "
                    "capacity, available_seats) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (exam_id, user["id"], slot_date, start_time, end_time, capacity, capacity))
            flash("Slot created.", "success")
            return redirect(url_for("examiner_slots", exam_id=exam_id))
    slots = query("SELECT * FROM slots WHERE exam_id = ? AND examiner_id = ? "
                  "ORDER BY slot_date, start_time", (exam_id, user["id"]))
    return render_template("examiner_slots.html", exam=exam, slots=slots)


@app.route("/examiner/slots/<int:slot_id>/edit", methods=["GET", "POST"])
@login_required("examiner")
def examiner_slot_edit(slot_id):
    user = current_user()
    slot = own_slot(slot_id, user["id"])
    has_bookings = count("SELECT COUNT(*) FROM bookings WHERE slot_id = ?", (slot_id,)) > 0
    if slot["exam_status"] not in ("Draft", "Slot Creation") or has_bookings:
        flash("This slot can no longer be changed (booking has started or it has bookings).", "danger")
        return redirect(url_for("examiner_slots", exam_id=slot["exam_id"]))
    values = dict(slot)
    if request.method == "POST":
        values = request.form
        slot_date = request.form.get("slot_date", "")
        start_time = request.form.get("start_time", "")
        end_time = request.form.get("end_time", "")
        capacity = to_int(request.form.get("capacity"))
        if not valid_date(slot_date) or not valid_time(start_time) or not valid_time(end_time):
            flash("Please enter a valid date, start time and end time.", "danger")
        elif start_time >= end_time:
            flash("End time must be after start time.", "danger")
        elif capacity is None or capacity < 1:
            flash("Capacity must be at least 1.", "danger")
        else:
            execute("UPDATE slots SET slot_date = ?, start_time = ?, end_time = ?, capacity = ?, "
                    "available_seats = ?, status = 'Available' WHERE id = ?",
                    (slot_date, start_time, end_time, capacity, capacity, slot_id))
            flash("Slot updated.", "success")
            return redirect(url_for("examiner_slots", exam_id=slot["exam_id"]))
    return render_template("examiner_slot_edit.html", slot=slot, values=values)


@app.route("/examiner/slots/<int:slot_id>/delete", methods=["POST"])
@login_required("examiner")
def examiner_slot_delete(slot_id):
    user = current_user()
    slot = own_slot(slot_id, user["id"])
    has_bookings = count("SELECT COUNT(*) FROM bookings WHERE slot_id = ?", (slot_id,)) > 0
    if slot["exam_status"] not in ("Draft", "Slot Creation") or has_bookings:
        flash("This slot can no longer be removed (booking has started or it has bookings).", "danger")
    else:
        execute("DELETE FROM slots WHERE id = ?", (slot_id,))
        flash("Slot removed.", "success")
    return redirect(url_for("examiner_slots", exam_id=slot["exam_id"]))


# ------------------------------------------------ examiner: bookings and evaluate
@app.route("/examiner/bookings")
@login_required("examiner")
def examiner_bookings():
    user = current_user()
    bookings = booking_rows("WHERE s.examiner_id = ? AND b.status IN ('Booked', 'Completed')",
                            (user["id"],))
    return render_template("examiner_bookings.html", bookings=bookings)


@app.route("/examiner/bookings/<int:booking_id>/evaluate", methods=["GET", "POST"])
@login_required("examiner")
def examiner_evaluate(booking_id):
    user = current_user()
    # the examiner_id check makes sure the examiner can only open their own students
    rows = booking_rows("WHERE b.id = ? AND s.examiner_id = ?", (booking_id, user["id"]))
    if not rows:
        abort(404)
    booking = rows[0]
    if booking["status"] == "Cancelled":
        flash("This booking was cancelled.", "danger")
        return redirect(url_for("examiner_bookings"))
    if booking["exam_status"] not in ("Booking Open", "Closed"):
        flash("Evaluation is allowed only while the examination is Booking Open or Closed.", "danger")
        return redirect(url_for("examiner_bookings"))
    rubrics = query("SELECT * FROM rubrics WHERE exam_id = ? ORDER BY id", (booking["exam_id"],))
    if not rubrics:
        flash("The admin has not added rubric criteria for this examination yet.", "danger")
        return redirect(url_for("examiner_bookings"))
    old = {r["rubric_id"]: r["marks"] for r in
           query("SELECT * FROM scores WHERE booking_id = ?", (booking_id,))}
    if request.method == "POST":
        remarks = request.form.get("remarks", "").strip()
        given = {}
        error = None
        for r in rubrics:
            marks = to_float(request.form.get("score_%d" % r["id"]))
            if marks is None or marks < 0 or marks > r["max_marks"]:
                error = 'Marks for "%s" must be a number from 0 to %s.' % (r["criterion"], r["max_marks"])
                break
            given[r["id"]] = marks
        if error:
            flash(error, "danger")
            old = {r["id"]: request.form.get("score_%d" % r["id"], "") for r in rubrics}
        else:
            db = get_db()
            db.execute("DELETE FROM scores WHERE booking_id = ?", (booking_id,))
            for rubric_id, marks in given.items():
                db.execute("INSERT INTO scores (booking_id, rubric_id, marks) VALUES (?, ?, ?)",
                           (booking_id, rubric_id, marks))
            db.execute("UPDATE bookings SET total_marks = ?, remarks = ?, status = 'Completed' WHERE id = ?",
                       (sum(given.values()), remarks, booking_id))
            db.commit()
            flash("Marks saved.", "success")
            return redirect(url_for("examiner_bookings"))
    return render_template("examiner_evaluate.html", booking=booking, rubrics=rubrics, old=old)


# ------------------------------------------------------------- student pages
@app.route("/student/exams")
@login_required("student")
def student_exams():
    q = request.args.get("q", "").strip()
    exam_type = request.args.get("exam_type", "").strip()
    sql = ("SELECT e.*, c.name AS course_name, c.code AS course_code FROM exams e "
           "JOIN courses c ON c.id = e.course_id WHERE e.status != 'Draft'")
    args = []
    if q:
        sql += " AND (e.name LIKE ? OR c.name LIKE ? OR c.code LIKE ?)"
        args += ["%" + q + "%"] * 3
    if exam_type:
        sql += " AND e.exam_type = ?"
        args.append(exam_type)
    exams = query(sql + " ORDER BY e.booking_start", args)
    return render_template("student_exams.html", exams=exams, q=q, exam_type=exam_type,
                           exam_types=EXAM_TYPES)


@app.route("/student/exams/<int:exam_id>")
@login_required("student")
def student_exam_detail(exam_id):
    user = current_user()
    exam = query("SELECT e.*, c.name AS course_name, u.name AS examiner_name FROM exams e "
                 "JOIN courses c ON c.id = e.course_id JOIN users u ON u.id = e.examiner_id "
                 "WHERE e.id = ? AND e.status != 'Draft'", (exam_id,), one=True)
    if exam is None:
        abort(404)
    slots = query("SELECT * FROM slots WHERE exam_id = ? ORDER BY slot_date, start_time", (exam_id,))
    my_booking = query(
        "SELECT b.* FROM bookings b JOIN slots s ON s.id = b.slot_id "
        "WHERE b.student_id = ? AND s.exam_id = ? AND b.status IN ('Booked', 'Completed')",
        (user["id"], exam_id), one=True)
    booking_open = exam["status"] == "Booking Open" and exam["booking_start"] <= today() <= exam["booking_end"]
    return render_template("student_exam_detail.html", exam=exam, slots=slots,
                           my_booking=my_booking, booking_open=booking_open)


@app.route("/student/slots/<int:slot_id>/book", methods=["POST"])
@login_required("student")
def student_book(slot_id):
    user = current_user()
    slot = query("SELECT s.*, e.status AS exam_status, e.booking_start, e.booking_end FROM slots s "
                 "JOIN exams e ON e.id = s.exam_id WHERE s.id = ?", (slot_id,), one=True)
    if slot is None:
        abort(404)
    duplicate = query(
        "SELECT b.id FROM bookings b JOIN slots s ON s.id = b.slot_id "
        "WHERE b.student_id = ? AND s.exam_id = ? AND b.status IN ('Booked', 'Completed')",
        (user["id"], slot["exam_id"]), one=True)
    error = None
    if slot["exam_status"] != "Booking Open":
        error = "Booking is not open for this examination."
    elif not (slot["booking_start"] <= today() <= slot["booking_end"]):
        error = "Today is outside the booking period."
    elif slot["available_seats"] < 1 or slot["status"] != "Available":
        error = "This slot is full."
    elif duplicate:
        error = "You already have a booking for this examination."
    if error:
        flash(error, "danger")
    else:
        db = get_db()
        db.execute("INSERT INTO bookings (student_id, slot_id, booking_date, status) VALUES (?, ?, ?, 'Booked')",
                   (user["id"], slot_id, datetime.now().strftime("%Y-%m-%d %H:%M")))
        # one seat less; when no seats are left the slot becomes Full automatically
        db.execute("UPDATE slots SET available_seats = available_seats - 1, "
                   "status = CASE WHEN available_seats - 1 <= 0 THEN 'Full' ELSE 'Available' END "
                   "WHERE id = ?", (slot_id,))
        db.commit()
        flash("Slot booked successfully.", "success")
    return redirect(url_for("student_exam_detail", exam_id=slot["exam_id"]))
