# ===========================================================
# App Creation and Launch
# ===========================================================

from flask import Flask, render_template, request, flash, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import html

from app.helpers.session import init_session
from app.helpers.db import connect_db
from app.helpers.errors import register_error_handlers, not_found_error
from app.helpers.auth import login_required


# Create the app
app = Flask(__name__)

# Setup a session for messages, etc.
init_session(app)

# Handle 404 and 500 errors
register_error_handlers(app)


# -----------------------------------------------------------
# Home page route
# -----------------------------------------------------------
@app.get("/")
def index():
    # TODO: Home page if signed in
    if "userid" in session:
        with connect_db() as client:
            # Incomplete tasks
            sql_incomplete = """
                SELECT *
                FROM tasks
                WHERE userid=? AND completed=0
                ORDER BY priority DESC
            """
            # Completed tasks
            sql_completed = """
                SELECT *
                FROM tasks
                WHERE userid=? AND completed=1
                ORDER BY priority DESC
            """
            values = [session["userid"]]
            incomplete = client.execute(sql_incomplete, values)
            complete = client.execute(sql_completed, values)

            return render_template(
                "pages/home.jinja", tasks=incomplete.rows, completedTasks=complete.rows
            )
    else:
        return render_template("pages/default.jinja")


# -----------------------------------------------------------
# About page route
# -----------------------------------------------------------
@app.get("/about/")
def about():
    return render_template("pages/about.jinja")


# -----------------------------------------------------------
# User registration form route
# -----------------------------------------------------------
@app.get("/register")
def register_form():
    return render_template("pages/register.jinja")


# -----------------------------------------------------------
# User login form route
# -----------------------------------------------------------
@app.get("/login")
def login_form():
    return render_template("pages/login.jinja")


# -----------------------------------------------------------
# Route for adding a task, using data posted from a form
# - Restricted to logged in users
# -----------------------------------------------------------
@app.post("/add")
@login_required
def add_a_task():
    # Get the data from the form
    name = request.form.get("name")
    priority = request.form.get("priority")

    print(name, priority)

    # Sanitise the inputs
    name = html.escape(name)

    with connect_db() as client:
        # Add the thing to the DB
        sql = "INSERT INTO tasks (name, priority, userid) VALUES (?, ?, ?)"
        values = [name, priority, session["userid"]]
        client.execute(sql, values)

        # Go back to the home page
        flash(f"Task '{name}' added", "success")
        return redirect("/")


# -----------------------------------------------------------
# Route for deleting a task, Id given in the route
# - Restricted to logged in users
# -----------------------------------------------------------
@app.get("/delete/<int:id>")
@login_required
def delete_a_task(id):
    with connect_db() as client:
        # Delete the thing from the DB only if we own it
        sql = "DELETE FROM tasks WHERE id=? AND userid=?"
        values = [id, session["userid"]]
        client.execute(sql, values)

        # Go back to the home page
        flash("Task deleted", "warning")
        return redirect("/")


@app.get("/toggle/<int:id>")
@login_required
def toggle_a_task(id):
    with connect_db() as client:
        # Toggle the completed boolean
        sql = "UPDATE tasks SET completed = NOT completed WHERE id=? AND userid=?"
        values = [id, session["userid"]]
        client.execute(sql, values)

        # Go back to the home page
        return redirect("/")


# -----------------------------------------------------------
# Route for adding a user when registration form submitted
# -----------------------------------------------------------
@app.post("/add-user")
def add_user():
    # Get the data from the form
    username = request.form.get("username")
    password = request.form.get("password")

    # Sanitise the inputs)
    username = html.escape(username)

    # Hash the password
    hash = generate_password_hash(password)

    with connect_db() as client:
        # Add the thing to the DB
        sql = "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)"
        values = [username, hash]
        result = client.execute(sql, values)

        if result.rows_affected == 0:
            flash("Username already exists.", "error")
            return redirect("/signup/")
        else:
            # Handle session
            session["userid"] = result.last_insert_rowid
            session["username"] = username

            flash(f"User {username} registered successfully", "success")
            return redirect("/")


# -----------------------------------------------------------
# Route for processing a user login
# -----------------------------------------------------------
@app.post("/login-user")
def login_user():
    # Get the login form data
    username = request.form.get("username")
    password = request.form.get("password")

    with connect_db() as client:
        # Attempt to find a record for that user
        sql = "SELECT * FROM users WHERE username = ?"
        values = [username]
        result = client.execute(sql, values)

        # Did we find a record?
        if result.rows:
            # Yes, so check password
            user = result.rows[0]
            hash = user.password

            # Hash matches?
            if check_password_hash(hash, password):
                # Yes, so save info in the session
                session["userid"] = user.id
                session["username"] = user.username

                # And head back to the home page
                flash("Login successful", "success")
                return redirect("/")

        # Either username not found, or password was wrong
        flash("Invalid credentials", "error")
        return redirect("/login")


# -----------------------------------------------------------
# Route for processing a user logout
# -----------------------------------------------------------
@app.get("/logout")
def logout():
    # Clear the details from the session
    session.pop("userid", None)
    session.pop("username", None)

    # And head back to the home page
    flash("Logged out successfully", "success")
    return redirect("/")
