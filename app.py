from flask import Flask, render_template, request, redirect, url_for, session
import os
from dotenv import load_dotenv
from supabase import create_client, Client

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret")

# Load environment variables
load_dotenv()

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
        return render_template("login.html", error="Invalid credentials")


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

    if supabase is None:
        return render_template("signup.html", error="Supabase is not configured")

    try:
        supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {"name": name}
            },
        })
        return redirect(url_for("success", message="Account created successfully! Please login to continue."))
    except Exception as e:
        return render_template("signup.html", error="Failed to create account")


@app.route("/home", methods=["GET"]) 
def home():
    if not is_authenticated():
        return redirect(url_for("login_page"))
    return render_template("home.html", user_email=session.get("user_email"))


@app.route("/success", methods=["GET"]) 
def success():
    message = request.args.get("message", "Successfully submitted!")
    return render_template("success.html", message=message)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
