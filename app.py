from flask import Flask, render_template, request, redirect, url_for, session
import os
import mimetypes
from dotenv import load_dotenv
from supabase import create_client, Client

# Fix MIME type for CSS files
mimetypes.add_type('text/css', '.css')

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


@app.route("/health")
def health_check():
    return {"status": "ok", "message": "VIT Switch Flask App is running!"}


@app.route("/admin/users")
def admin_users():
    """View all users - Admin endpoint"""
    if supabase is None:
        return {"error": "Supabase not configured"}, 500
    
    try:
        # Get users using Supabase admin API
        response = supabase.auth.admin.list_users()
        users = []
        
        for user in response:
            users.append({
                "id": user.id,
                "email": user.email,
                "created_at": str(user.created_at),
                "last_sign_in": str(user.last_sign_in_at) if user.last_sign_in_at else "Never",
                "email_confirmed": user.email_confirmed_at is not None
            })
        
        return {
            "total_users": len(users),
            "users": users,
            "message": f"Found {len(users)} registered users"
        }
    except Exception as e:
        return {"error": f"Failed to fetch users: {str(e)}"}, 500


@app.route("/", methods=["GET"]) 
def login_page():
    try:
        if is_authenticated():
            return redirect(url_for("home"))
        return render_template("login.html")
    except Exception as e:
        return f"Error loading login page: {str(e)}", 500


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
    try:
        if not is_authenticated():
            return redirect(url_for("login_page"))
        user_email = session.get("user_email", "Unknown User")
        return render_template("home.html", user_email=user_email)
    except Exception as e:
        return f"Error loading home page: {str(e)}", 500


@app.route("/success", methods=["GET"]) 
def success():
    message = request.args.get("message", "Successfully submitted!")
    return render_template("success.html", message=message)


# Placeholder routes for home page links
@app.route("/reviews")
def reviews():
    return render_template("reviews.html")

@app.route("/faculty-review")
def faculty_review():
    return render_template("faculty_review.html")

@app.route("/course-review")
def course_review():
    return render_template("course_review.html")

@app.route("/batch-switch")
def batch_switch():
    return render_template("batch_switch.html")

@app.route("/eduvids")
def eduvids():
    return render_template("eduvids.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
