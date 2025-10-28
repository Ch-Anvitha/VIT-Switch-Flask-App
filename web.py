from flask import Flask, render_template, request, redirect, url_for, session
import os
from dotenv import load_dotenv
from supabase import create_client, Client

app = Flask(__name__)
app.secret_key = "dev-secret"

# Load environment variables
load_dotenv()

# DEV MODE - Set to True to bypass email confirmation
DEV_MODE = True

# Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
supabase: Client | None = None
if SUPABASE_URL and SUPABASE_ANON_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


def is_authenticated():
    return bool(session.get("user_email"))


@app.route("/", methods=["GET"]) 
def login_page():
    if is_authenticated():
        return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/auth/login", methods=["POST"]) 
def auth_login():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    if not email or not password:
        return render_template("login.html", error="Invalid credentials")

    # DEV MODE BYPASS - Allow any login for testing
    if DEV_MODE:
        if len(password) >= 6:  # Basic validation
            session["user_email"] = email
            session["access_token"] = "dev-mode-token"
            return redirect(url_for("home"))
        else:
            return render_template("login.html", error="Password must be at least 6 characters")

    if supabase is None:
        return render_template("login.html", error="Supabase is not configured")

    try:
        result = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password,
        })
        session["user_email"] = email
        session["access_token"] = getattr(result.session, "access_token", None)
        return redirect(url_for("home"))
    except Exception as e:
        error_message = str(e)
        print(f"Login error: {error_message}")  # Debug logging
        print(f"Error type: {type(e)}")
        
        # Check for email confirmation issues
        if any(keyword in error_message.lower() for keyword in ["email not confirmed", "email_not_confirmed", "confirm your email"]):
            return render_template("login.html", error="Please check your email and confirm your account before logging in")
        elif "invalid login credentials" in error_message.lower():
            # This could be unconfirmed email or wrong password
            return render_template("login.html", error="Invalid credentials. If you just signed up, please confirm your email first. Otherwise check your email/password")
        else:
            # Show actual error for debugging
            return render_template("login.html", error=f"Login failed: {error_message}")


@app.route("/auth/logout", methods=["POST"]) 
def auth_logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/signup", methods=["GET", "POST"]) 
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    confirm = request.form.get("confirmPassword", "").strip()
    if not name or not email or not password or password != confirm or len(password) < 6:
        return render_template("signup.html", error="Invalid sign up details")

    # DEV MODE BYPASS - Skip Supabase signup
    if DEV_MODE:
        return redirect(url_for("success", message="Account created successfully! You can now login."))

    if supabase is None:
        return render_template("signup.html", error="Supabase is not configured")

    try:
        supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {"name": name},
                "email_redirect_to": None
            },
        })
        return redirect(url_for("success", message="Account created! Please check your email and click the confirmation link before logging in."))
    except Exception as e:
        error_msg = str(e)
        if "already registered" in error_msg.lower():
            return render_template("signup.html", error="Email already registered. Please login or use a different email")
        return render_template("signup.html", error=f"Failed to create account: {error_msg}")


@app.route("/home", methods=["GET"]) 
def home():
    if not is_authenticated():
        return redirect(url_for("login_page"))
    return render_template("home.html", user_email=session.get("user_email"))


@app.route("/success", methods=["GET"]) 
def success():
    message = request.args.get("message", "Successfully submitted!")
    return render_template("success.html", message=message)


@app.route("/confirm-email-help", methods=["GET"])
def confirm_email_help():
    return render_template("confirm_email_help.html")


@app.route("/reviews", methods=["GET"])
def reviews():
    if not is_authenticated():
        return redirect(url_for("login_page"))
    return render_template("reviews.html", user_email=session.get("user_email"))


@app.route("/faculty-review", methods=["GET", "POST"])
def faculty_review():
    if not is_authenticated():
        return redirect(url_for("login_page"))
    if request.method == "GET":
        return render_template("faculty_review.html", user_email=session.get("user_email"))
    # Handle POST - submit review
    return redirect(url_for("success", message="Faculty review submitted successfully!"))


@app.route("/course-review", methods=["GET", "POST"])
def course_review():
    if not is_authenticated():
        return redirect(url_for("login_page"))
    if request.method == "GET":
        return render_template("course_review.html", user_email=session.get("user_email"))
    # Handle POST - submit review
    return redirect(url_for("success", message="Course review submitted successfully!"))


@app.route("/batch-switch", methods=["GET", "POST"])
def batch_switch():
    if not is_authenticated():
        return redirect(url_for("login_page"))
    if request.method == "GET":
        return render_template("batch_switch.html", user_email=session.get("user_email"))
    # Handle POST - submit batch switch request
    return redirect(url_for("success", message="Batch switch request submitted successfully!"))


@app.route("/eduvids", methods=["GET"])
def eduvids():
    if not is_authenticated():
        return redirect(url_for("login_page"))
    return render_template("eduvids.html", user_email=session.get("user_email"))


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not is_authenticated():
        return redirect(url_for("login_page"))
    return render_template("dashboard.html", user_email=session.get("user_email"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
