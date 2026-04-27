# 🔐 Secure Student Records (SQL Security Project)

A secure, role-based web application built with **Flask** and **SQL Server** that demonstrates database security concepts such as authentication, role-based access control (RBAC), session handling, and safe database access.

---

## Project overview

This project implements a Secure Student Records Management System (SRMS) GUI/web app that follows core security requirements for handling sensitive academic data (students, grades, attendance, users and roles). The app enforces role checks at the application level and exposes a small REST-like API for the frontend to interact with the database.

---

## What is implemented (current state)

* **Authentication & Session management**

  * Login and logout endpoints and session handling.
  * Passwords are hashed using SHA-256 before storing/verification.

* **Role-Based Access Control (RBAC)**

  * Role and clearance stored in session after login.
  * Endpoints check `session['role']` to allow/deny actions (e.g., only `Admin` can create users or add students).

* **REST-like endpoints / Application API**

  * `/api/users` (GET/POST) — list users and create users (admin only).
  * `/api/users/<id>` (PUT) — update user role/clearance/is_active (admin only).
  * `/api/students` (GET/POST) — list students (role-based visibility) and add students (admin only).
  * `/api/ta-assign` (POST/DELETE) — assign/unassign TAs to courses (Admin/Instructor).

* **Frontend templates**

  * Jinja2 templates for pages such as `dashboard.html` and other role-specific views.
  * Tailwind-style responsive layout for the dashboard.

* **Database connection**

  * Uses `pyodbc` to connect to SQL Server with parameterized queries (prepared statements using `?`) to reduce SQL injection risk.

* **Error handling**

  * JSON error responses and redirects for unauthorized access.

---

## Key features / Highlights

* Secure login flow with hashed password comparison.
* Session-based role and clearance enforcement across pages and APIs.
* Admin-only management functions for users and students.
* TA assignment workflow endpoints to manage TA-course relationships.
* Templates include dynamic UI elements showing current user, role and clearance.

---

## Technologies & libraries used

* Python 3.x
* Flask (web framework)
* pyodbc (SQL Server connectivity)
* Jinja2 (Flask templating)
* TailwindCSS / utility classes in templates (for layout & design)
* SQL Server (database)



---

## Installation & run (local)

1. Create a Python virtual environment and activate it:

```bash
python -m venv venv
source venv/bin/activate  # on Windows: venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure your database connection string inside `app.py` or use an environment variable.

4. Run the app:

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

## Security notes & recommendations

* Passwords are hashed with SHA-256 in the application. For production use, prefer a slow password hashing function (e.g., `bcrypt`, `argon2`) and include salts.
* Sensitive columns (Student ID, grades, phone) should be encrypted at rest in the database (AES) per the project specification.
* Always use parameterized queries (already used in this codebase) and avoid string concatenation for SQL statements.
* Store connection strings and secrets in environment variables (`.env`) and add `.env` to `.gitignore`.

---

## Next steps / Improvements

* Implement AES encryption for sensitive fields in the database (using SQL Server `EncryptByKey` / `DecryptByKey` or application-level encryption).
* Add stored procedures and database-side role checks for a stronger defense-in-depth (as required by the course specification).
* Implement inference control (query set size control) and flow control logic on the DB side and through views.
* Replace SHA-256 with `bcrypt`/`argon2` and add password strength checks and rate limiting on login attempts.

---

## Author

**Karim Mohamed** — Secure Student Records Project


