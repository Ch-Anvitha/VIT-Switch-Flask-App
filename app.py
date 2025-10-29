from flask import Flask, render_template, request, redirect, url_for, session
import os
import json
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


@app.route("/debug/env")
def debug_env():
    """Debug endpoint to check environment variables"""
    return {
        "SUPABASE_URL": bool(os.getenv("SUPABASE_URL")),
        "SUPABASE_ANON_KEY": bool(os.getenv("SUPABASE_ANON_KEY")),
        "SUPABASE_SERVICE_ROLE_KEY": bool(os.getenv("SUPABASE_SERVICE_ROLE_KEY")),
        "service_role_key_length": len(os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")),
        "FLASK_SECRET_KEY": bool(os.getenv("FLASK_SECRET_KEY"))
    }


@app.route("/admin/users")
def admin_users():
    """View all users - Admin endpoint"""
    # Check admin authentication
    admin_password = request.args.get("admin_password") or request.headers.get("X-Admin-Password")
    if not admin_password or admin_password != "admin123":
        return {"error": "Admin password required"}, 401

    # For now, return a message since we can't access admin API with anon key
    # In production, you'd use service role key for admin operations
    return {
        "message": "Admin access granted",
        "note": "User data is managed through Supabase Dashboard at https://supabase.com/dashboard/project/igocqbidhxuqygvzxoen/auth/users",
        "total_users": "Check Supabase dashboard for user count",
        "users": []
    }


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
    print(f"[DEBUG] Login attempt for email: {email}")

    if not email or not password:
        return render_template("login.html", error="Please enter both email and password")

    if supabase is None:
        print("[DEBUG] Supabase client is not configured")
        return render_template("login.html", error="Supabase is not configured")

    try:
        print(f"[DEBUG] Attempting login with Supabase")
        result = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password,
        })
        print(f"[DEBUG] Login successful for {email}")

        # Store session data
        session.clear()  # Clear any existing session data
        session["user_email"] = email

        # Safely get session data
        if hasattr(result, 'session') and result.session:
            session["access_token"] = result.session.access_token
            print(f"[DEBUG] Access token stored")
        else:
            print(f"[DEBUG] No session data in result")

        print("[DEBUG] Session data stored successfully")
        return redirect(url_for("home"))

    except Exception as e:
        error_message = str(e)
        print(f"[DEBUG] Login error details: {error_message}")

        # Check for specific error types and provide helpful messages
        if any(keyword in error_message.lower() for keyword in ["email not confirmed", "email_not_confirmed", "confirm your email"]):
            return render_template("login.html", error="Please check your email and confirm your account before logging in")
        elif "invalid login credentials" in error_message.lower() or "invalid_credentials" in error_message.lower():
            return render_template("login.html", error="Invalid credentials. If you just signed up, please confirm your email first. Otherwise check your email/password")
        elif "rate limit" in error_message.lower() or "security purposes" in error_message.lower():
            return render_template("login.html", error="Too many login attempts. Please wait a moment and try again")
        elif "network" in error_message.lower() or "connection" in error_message.lower():
            return render_template("login.html", error="Network error. Please check your internet connection and try again")
        else:
            return render_template("login.html", error="Login failed. Please try again later")


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
        result = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {"name": name},
                "email_redirect_to": "http://localhost:5000/confirm-email-help"
            },
        })
        print(f"[DEBUG] Signup result: {result}")
        return redirect(url_for("success", message="Account created successfully! Please check your email and confirm your account before logging in."))
    except Exception as e:
        error_msg = str(e)
        print(f"[DEBUG] Signup error: {error_msg}")
        
        # Handle specific error types with user-friendly messages
        if "already registered" in error_msg.lower():
            return render_template("signup.html", error="Email already registered. Please login or use a different email")
        elif "rate limit" in error_msg.lower() or "32 seconds" in error_msg.lower() or "security purposes" in error_msg.lower():
            return render_template("signup.html", error="Please wait a moment before creating another account. Try again in 30-60 seconds.")
        elif "invalid email" in error_msg.lower():
            return render_template("signup.html", error="Please enter a valid email address")
        elif "weak password" in error_msg.lower() or "password" in error_msg.lower():
            return render_template("signup.html", error="Password must be at least 6 characters long and contain letters and numbers")
        elif "network" in error_msg.lower() or "connection" in error_msg.lower():
            return render_template("signup.html", error="Network error. Please check your internet connection and try again")
        else:
            return render_template("signup.html", error="Unable to create account at this time. Please try again later")


@app.route("/confirm-email-help", methods=["GET"])
def confirm_email_help():
    """Help page for email confirmation"""
    return render_template("confirm_email_help.html")


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

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")

    password = request.form.get("admin_password", "").strip()
    if password == "admin123":  # Simple admin password
        session["admin_logged_in"] = True
        return redirect(url_for("admin_dashboard"))
    else:
        return render_template("admin_login.html", error="Invalid password")

@app.route("/admin")
def admin_redirect():
    return redirect(url_for("admin_login"))

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    # Get user stats for dashboard - real-time data access
    total_users = 0
    confirmed_users = 0
    recent_users = 0
    users = []

    # For real-time data, you need SUPABASE_SERVICE_ROLE_KEY instead of SUPABASE_ANON_KEY
    service_role_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    print(f"[DEBUG] Service role key present: {bool(service_role_key)}")

    if service_role_key and SUPABASE_URL:
        try:
            # Use service role key for admin operations
            supabase_admin = create_client(SUPABASE_URL, service_role_key)
            print("[DEBUG] Created admin client with service role key")

            # Try alternative approach - use REST API directly
            import requests
            import json
            headers = {
                'Authorization': f'Bearer {service_role_key}',
                'apikey': service_role_key,
                'Content-Type': 'application/json'
            }

            api_url = f"{SUPABASE_URL}/auth/v1/admin/users"
            print(f"[DEBUG] Making direct API call to: {api_url}")

            response = requests.get(api_url, headers=headers)
            print(f"[DEBUG] Direct API response status: {response.status_code}")

            if response.status_code == 200:
                try:
                    response_data = response.json()
                    
                    # Handle different response formats
                    if isinstance(response_data, dict) and 'users' in response_data:
                        users = response_data['users']
                    elif isinstance(response_data, list):
                        users = response_data
                    else:
                        users = [response_data] if response_data else []
                        
                    total_users = len(users)
                    print(f"[DEBUG] Raw users data type: {type(users)}, length: {total_users}")
                    
                    # Process users safely
                    formatted_users = []
                    confirmed_users = 0
                    recent_users = 0
                    
                    from datetime import datetime, timedelta
                    thirty_days_ago = datetime.now() - timedelta(days=30)
                    
                    for user in users:
                        try:
                            # Ensure user is a dictionary
                            if isinstance(user, str):
                                continue  # Skip invalid user data
                            
                            user_dict = user if isinstance(user, dict) else vars(user) if hasattr(user, '__dict__') else {}
                            
                            # Extract user information safely
                            user_id = user_dict.get('id', '')
                            email = user_dict.get('email', '')
                            email_confirmed_at = user_dict.get('email_confirmed_at')
                            created_at = user_dict.get('created_at', '')
                            last_sign_in_at = user_dict.get('last_sign_in_at', '')
                            
                            # Count confirmed users
                            if email_confirmed_at:
                                confirmed_users += 1
                            
                            # Count recent users
                            if created_at:
                                try:
                                    created_date = datetime.fromisoformat(str(created_at).replace('Z', '+00:00'))
                                    if created_date > thirty_days_ago:
                                        recent_users += 1
                                except (ValueError, TypeError):
                                    pass
                            
                            formatted_users.append({
                                'id': str(user_id),
                                'email': str(email),
                                'email_confirmed': email_confirmed_at is not None,
                                'created_at': str(created_at),
                                'last_sign_in': str(last_sign_in_at)
                            })
                        except Exception as user_error:
                            print(f"[DEBUG] Error processing individual user: {user_error}")
                            continue
                    
                    users = formatted_users
                    print(f"[DEBUG] Successfully processed {len(users)} users via direct API, {confirmed_users} confirmed, {recent_users} recent")
                except Exception as e:
                    print(f"[DEBUG] Error processing user data: {str(e)}")
                    users = []
                    total_users = 0
                    confirmed_users = 0
                    recent_users = 0
            else:
                print(f"[DEBUG] Direct API failed: {response.text}")
                # Fallback to old method
                response = supabase_admin.auth.admin.list_users()
                print(f"[DEBUG] Fallback method response: {type(response)}")

                if hasattr(response, 'data') and response.data:
                    users_data = response.data
                    total_users = len(users_data)
                    
                    # Process fallback users safely
                    formatted_users = []
                    confirmed_users = 0
                    recent_users = 0
                    
                    from datetime import datetime, timedelta
                    thirty_days_ago = datetime.now() - timedelta(days=30)
                    
                    for user in users_data:
                        try:
                            user_id = getattr(user, 'id', '')
                            email = getattr(user, 'email', '')
                            email_confirmed_at = getattr(user, 'email_confirmed_at', None)
                            created_at = getattr(user, 'created_at', None)
                            last_sign_in_at = getattr(user, 'last_sign_in_at', None)
                            
                            # Count confirmed users
                            if email_confirmed_at:
                                confirmed_users += 1
                            
                            # Count recent users
                            if created_at:
                                try:
                                    created_date = datetime.fromisoformat(str(created_at).replace('Z', '+00:00'))
                                    if created_date > thirty_days_ago:
                                        recent_users += 1
                                except (ValueError, TypeError):
                                    pass
                            
                            formatted_users.append({
                                'id': str(user_id),
                                'email': str(email),
                                'email_confirmed': email_confirmed_at is not None,
                                'created_at': str(created_at) if created_at else '',
                                'last_sign_in': str(last_sign_in_at) if last_sign_in_at else ''
                            })
                        except Exception as user_error:
                            print(f"[DEBUG] Error processing fallback user: {user_error}")
                            continue
                    
                    users = formatted_users
                    print(f"[DEBUG] Successfully processed {len(users)} users via fallback, {confirmed_users} confirmed, {recent_users} recent")

        except Exception as e:
            print(f"[DEBUG] Failed to fetch admin data with service role key: {e}")
            error = f"Failed to load user data: {str(e)}"
    else:
        print("[DEBUG] No service role key configured")
        # No service role key configured - show helpful message
        error = "Real-time user data requires SUPABASE_SERVICE_ROLE_KEY. For now, use the Supabase Dashboard links below to view user data."

    return render_template("admin_dashboard.html",
                          total_users=total_users,
                          confirmed_users=confirmed_users,
                          recent_users=recent_users,
                          users=users,
                          error=error if 'error' in locals() and error else None)

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# Admin function to check users (temporary for debugging)
def check_users():
    """Debug function to check users in database"""
    try:
        # This will only work if you have service role key
        import os
        from dotenv import load_dotenv
        from supabase import create_client, Client

        load_dotenv()
        SUPABASE_URL = os.getenv("SUPABASE_URL", "")
        SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")

        if not SUPABASE_URL or not SUPABASE_ANON_KEY:
            return {"error": "Supabase not configured"}

        supabase_admin = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

        # Try to list users - this might fail due to permissions
        response = supabase_admin.auth.admin.list_users()
        users = []

        for user in response:
            users.append({
                "id": str(user.id),
                "email": user.email,
                "created_at": str(user.created_at),
                "confirmed": user.email_confirmed_at is not None,
                "last_sign_in": str(user.last_sign_in_at) if user.last_sign_in_at else None
            })

        return {
            "success": True,
            "total_users": len(users),
            "users": users
        }

    except Exception as e:
        return {"error": f"Failed to fetch users: {str(e)}"}

if __name__ == "__main__":
    # Quick user check for debugging
    print("=== USER CHECK DEBUG ===")
    result = check_users()
    if "error" in result:
        print(f"Error: {result['error']}")
    else:
        print(f"Found {result['total_users']} users:")
        for user in result['users']:
            print(f"  - {user['email']} (confirmed: {user['confirmed']})")

    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV") != "production"
    print(f"[DEBUG] Starting server on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
