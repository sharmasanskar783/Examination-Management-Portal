# Examination Management Portal (EMP)

Web app where an Admin manages courses, examinations and rubrics, Examiners create
slots and evaluate students, and Students book slots and view results.

## Tech
Flask, Jinja2, HTML, Bootstrap 5 (CDN), SQLite (sqlite3). No JavaScript.

## Run locally
1. python -m venv venv
2. venv\Scripts\activate (Mac/Linux: source venv/bin/activate)
3. pip install -r requirements.txt
4. flask --app app run --debug
5. Open http://127.0.0.1:5000

The database (emp.db) is created automatically on first run.

## Default admin
Email: admin@emp.com Password: admin123

## Roles
Admin, Examiner (needs admin approval), Student.

## Folder structure
app.py (routes), db.py (database), templates/ (pages)

## AI declaration
(Write honestly where AI helped and what you wrote and tested yourself.)
