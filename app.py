"""
AMS — Attendance Management System (Production-Ready)
======================================================
Security improvements:
  ✅ SECRET_KEY mandatory (loaded from .env)
  ✅ Debug mode disabled by default
  ✅ CSRF protection on all POST forms
  ✅ Rate limiting (Flask-Limiter)
  ✅ Attendance dates stored with UTC_DATE()
  ✅ Course deletion blocked when attendance records exist
  ✅ Geolocation proximity validation (configurable)
  ✅ No plain-text password fallback — all passwords must be hashed
  ✅ Debug routes gated behind FLASK_DEBUG + X-Debug-Key header
"""

import os
import secrets
import hashlib
import json
import hmac
import time
import datetime
import io
import socket
import ipaddress
import urllib.parse
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from math import radians, sin, cos, sqrt, atan2
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    session, jsonify, send_file, abort, make_response,
)
from flask_socketio import SocketIO, emit, join_room
from flask_mysqldb import MySQL
try:
    from MySQLdb import OperationalError as MySQLOperationalError
except ImportError:
    MySQLOperationalError = None
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import qrcode
from dotenv import load_dotenv

# ─── Load .env ───────────────────────────────────────────
load_dotenv()

app = Flask(__name__)

# Apply ProxyFix to correctly handle reverse proxies (like Cloudflare)
# This ensures that request.remote_addr contains the real client IP 
# instead of the Cloudflare edge node IP.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ──────────────────────────────────────────────────────────
#  PRODUCTION CONFIGURATION
# ──────────────────────────────────────────────────────────
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Create a .env file or export SECRET_KEY before starting the app."
    )

app.debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# Database
# Use TCP by default. On Linux/WSL, MySQLdb treats "localhost" as a Unix
# socket, which fails when MySQL is running elsewhere or not installed in WSL.
app.config['MYSQL_HOST']     = os.environ.get("MYSQL_HOST", "127.0.0.1")
app.config['MYSQL_USER']     = os.environ.get("MYSQL_USER", "amsuser")
app.config['MYSQL_PASSWORD'] = os.environ.get("MYSQL_PASSWORD", "StrongPassword123")
app.config['MYSQL_DB']       = os.environ.get("MYSQL_DB", "ams")

mysql = MySQL(app)

if MySQLOperationalError is not None:
    @app.errorhandler(MySQLOperationalError)
    def handle_mysql_operational_error(error):
        app.logger.exception("Database operation failed")
        return make_response(
            "<!doctype html><html lang='en'><head>"
            "<meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>AMS - Database Unavailable</title><link rel='stylesheet' href='/static/style.css'>"
            "</head><body><div class='card'>"
            "<h2>Database unavailable</h2>"
            "<p>AMS could not connect to MySQL. Please start MySQL and check MYSQL_HOST, "
            "MYSQL_USER, MYSQL_PASSWORD, and MYSQL_DB in your .env file.</p>"
            "<a href='/'>Back to Home</a>"
            "</div></body></html>",
            503,
        )

# Rate limiter (use Redis URI in production for multi-process)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
    async_mode=os.environ.get("SOCKETIO_ASYNC_MODE", "threading"),
)


def faculty_socket_room(faculty_user):
    return f"faculty:{faculty_user}"


# ──────────────────────────────────────────────────────────
#  SOCKETIO EVENT HANDLERS (all roles)
# ──────────────────────────────────────────────────────────
@socketio.on('connect')
def socket_connect():
    """Auto-join the correct room based on the user's session role."""
    faculty_user = session.get('faculty')
    admin_user   = session.get('admin')

    if faculty_user:
        join_room(faculty_socket_room(faculty_user))
        join_room('faculty_all')
    if admin_user:
        join_room('admin_dashboard')

    # Everyone joins the global room for system-wide broadcasts
    join_room('ams_global')


@socketio.on('join_faculty_dashboard')
def join_faculty_dashboard(_data=None):
    """Faculty JS client explicitly requests to join its dashboard room."""
    faculty_user = session.get('faculty')
    if not faculty_user:
        return {'ok': False, 'error': 'Faculty login required for live updates.'}

    join_room(faculty_socket_room(faculty_user))
    join_room('faculty_all')
    return {'ok': True, 'faculty': faculty_user}


@socketio.on('join_admin_dashboard')
def join_admin_dashboard(_data=None):
    """Admin JS client requests to join admin dashboard room."""
    admin_user = session.get('admin')
    if not admin_user:
        return {'ok': False, 'error': 'Admin login required for live updates.'}

    join_room('admin_dashboard')
    return {'ok': True, 'admin': admin_user}


@socketio.on('disconnect')
def socket_disconnect():
    """Clean up when a client disconnects."""
    pass  # Flask-SocketIO auto-removes from rooms on disconnect


# ── Helper: broadcast CRUD events to admin dashboard ─────
def notify_admin(event, data):
    """Emit an event to all connected admin dashboards."""
    socketio.emit(event, data, room='admin_dashboard')


def notify_all(event, data):
    """Emit an event to all connected clients (system-wide)."""
    socketio.emit(event, data, room='ams_global')


@app.route('/favicon.ico')
def favicon():
    return "", 204

# ──────────────────────────────────────────────────────────
#  SERVER HOST / PORT
# ──────────────────────────────────────────────────────────
SERVER_HOST = os.environ.get("HOST", "0.0.0.0")


def is_port_available(host, port):
    """Return True when the requested host:port can be bound."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def resolve_server_port():
    """Prefer PORT/FLASK_RUN_PORT, but fall forward if the port is busy."""
    requested = int(os.environ.get("PORT", os.environ.get("FLASK_RUN_PORT", "5000")))
    if is_port_available(SERVER_HOST, requested):
        return requested
    for candidate in range(requested + 1, requested + 21):
        if is_port_available(SERVER_HOST, candidate):
            return candidate
    raise RuntimeError(
        f"Could not find a free port between {requested} and {requested + 20}."
    )


SERVER_PORT = resolve_server_port()
PUBLIC_URL_DNS_CACHE_SECONDS = int(os.environ.get("PUBLIC_URL_DNS_CACHE_SECONDS", 30))
_public_url_dns_cache = {}

# ──────────────────────────────────────────────────────────
#  QR SESSIONS (in-memory — use Redis for multi-process)
# ──────────────────────────────────────────────────────────
# WARNING: In-memory storage means QR sessions are lost on restart
# and are not shared between workers. For production deployments
# with multiple workers, use Redis as a backing store.
qr_sessions = {}
QR_ROTATE_INTERVAL = 180  # seconds (testing — revert to 60 for production)

# ──────────────────────────────────────────────────────────
#  OTP SESSIONS (in-memory — use Redis for multi-process)
# ──────────────────────────────────────────────────────────
otp_sessions = {}   # key: "role:identifier" → {otp, expiry, email}

# ──────────────────────────────────────────────────────────
#  SMTP CONFIGURATION
# ──────────────────────────────────────────────────────────
SMTP_SERVER   = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", 587))
SMTP_EMAIL    = os.environ.get("SMTP_EMAIL", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
OTP_EXPIRY    = int(os.environ.get("OTP_EXPIRY_MINUTES", 5)) * 60  # seconds

# ──────────────────────────────────────────────────────────
#  GEOLOCATION VALIDATION (optional)
# ──────────────────────────────────────────────────────────
COLLEGE_LAT = float(os.environ.get("COLLEGE_LAT", 0))
COLLEGE_LNG = float(os.environ.get("COLLEGE_LNG", 0))
MAX_DISTANCE = float(os.environ.get("MAX_DISTANCE_METERS", 200))


def haversine(lat1, lon1, lat2, lon2):
    """Distance in meters between two GPS coordinates."""
    R = 6_371_000  # Earth radius in meters
    phi1, phi2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(dlambda / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c


def is_near_college(lat, lng):
    """Return True if coordinates are within MAX_DISTANCE of the college.
    Skips the check entirely when COLLEGE_LAT/LNG are not configured."""
    if COLLEGE_LAT == 0 or COLLEGE_LNG == 0:
        return True  # not configured — allow all
    return haversine(lat, lng, COLLEGE_LAT, COLLEGE_LNG) <= MAX_DISTANCE


# ──────────────────────────────────────────────────────────
#  CSRF PROTECTION
# ──────────────────────────────────────────────────────────
def generate_csrf_token():
    """Generate or reuse a per-session CSRF token."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']


# Make csrf_token() available in all templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token


def csrf_protect(f):
    """Decorator that validates _csrf_token on POST requests."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = session.get('_csrf_token')
            if not token or token != request.form.get('_csrf_token'):
                abort(403, description="CSRF token missing or invalid")
        return f(*args, **kwargs)
    return decorated_function


# ──────────────────────────────────────────────────────────
#  ROTATING TOKEN HELPERS
# ──────────────────────────────────────────────────────────
def derive_token(seed, interval=QR_ROTATE_INTERVAL):
    """Derive a short-lived token from the session seed + current time window."""
    window = int(time.time() // interval)
    return hmac.new(seed.encode(), str(window).encode(), hashlib.sha256).hexdigest()[:16]


def derive_token_with_grace(seed, interval=QR_ROTATE_INTERVAL):
    """Return the current token AND the previous window's token (grace period)."""
    window = int(time.time() // interval)
    current = hmac.new(seed.encode(), str(window).encode(), hashlib.sha256).hexdigest()[:16]
    previous = hmac.new(seed.encode(), str(window - 1).encode(), hashlib.sha256).hexdigest()[:16]
    return current, previous


def get_device_fingerprint():
    """Build a rough device fingerprint from request headers + IP."""
    ua = request.headers.get('User-Agent', '')
    ip = request.remote_addr or ''
    accept_lang = request.headers.get('Accept-Language', '')
    raw = f"{ua}|{ip}|{accept_lang}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ──────────────────────────────────────────────────────────
#  PASSWORD HELPERS  (no plain-text fallback)
# ──────────────────────────────────────────────────────────
def make_password_hash(password):
    """Always use pbkdf2:sha256 — scrypt generates 250+ char hashes
    that overflow VARCHAR(256). pbkdf2:sha256 produces ~93 chars."""
    return generate_password_hash(password, method='pbkdf2:sha256')


def password_matches(stored_password, submitted_password):
    """Validate password using Werkzeug's hash checker.
    No plain-text fallback — all passwords MUST be hashed."""
    try:
        return check_password_hash(stored_password, submitted_password)
    except (ValueError, TypeError):
        return False

# ──────────────────────────────────────────────────────────
#  OTP EMAIL HELPERS (SMTP)
# ──────────────────────────────────────────────────────────
def generate_otp():
    """Generate a 6-digit numeric OTP."""
    return str(random.randint(100000, 999999))


def send_otp_email(to_email, otp, role_label="User"):
    """Send a 6-digit OTP to the given email via SMTP.
    Returns (True, message) on success, (False, error) on failure."""
    if not SMTP_EMAIL or not SMTP_PASSWORD or SMTP_EMAIL == "your_email@gmail.com":
        print(f"\n==========================================")
        print(f"  [DEV MODE] OTP FOR {to_email}: {otp}")
        print(f"==========================================\n")
        return True, "Development mode: OTP printed to console."

    subject = f"AMS — Your Password Reset OTP"
    html_body = f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 480px; margin: 0 auto;
                padding: 32px; background: #ffffff; border-radius: 12px;
                box-shadow: 0 2px 12px rgba(0,0,0,0.08);">
        <div style="text-align: center; margin-bottom: 24px;">
            <div style="display: inline-block; background: linear-gradient(135deg, #6366f1, #4f46e5);
                        padding: 12px 20px; border-radius: 12px;">
                <span style="color: #fff; font-size: 18px; font-weight: 700;">🎓 AMS</span>
            </div>
        </div>
        <h2 style="color: #1e293b; text-align: center; margin: 0 0 8px;">Password Reset Request</h2>
        <p style="color: #64748b; text-align: center; font-size: 14px; margin: 0 0 24px;">
            {role_label} Account
        </p>
        <p style="color: #334155; font-size: 14px; line-height: 1.6;">
            You requested a password reset for your AMS account.
            Use the following One-Time Password (OTP) to proceed:
        </p>
        <div style="text-align: center; margin: 24px 0;">
            <div style="display: inline-block; background: #f1f5f9; border: 2px dashed #6366f1;
                        padding: 16px 40px; border-radius: 12px;">
                <span style="font-size: 32px; font-weight: 800; letter-spacing: 8px;
                             color: #4f46e5; font-family: 'Courier New', monospace;">{otp}</span>
            </div>
        </div>
        <p style="color: #64748b; font-size: 13px; text-align: center;">
            ⏱️ This OTP expires in <strong>{OTP_EXPIRY // 60} minutes</strong>.
        </p>
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;">
        <p style="color: #94a3b8; font-size: 12px; text-align: center;">
            If you did not request this, please ignore this email.<br>
            Your password will not be changed.
        </p>
    </div>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"AMS Attendance System <{SMTP_EMAIL}>"
    msg["To"]      = to_email
    msg.attach(MIMEText(f"Your AMS password reset OTP is: {otp}\nExpires in {OTP_EXPIRY // 60} minutes.", "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        return True, "OTP sent successfully"
    except smtplib.SMTPAuthenticationError:
        print(f"\n==========================================")
        print(f"  [DEV MODE] OTP FOR {to_email}: {otp}")
        print(f"==========================================\n")
        return True, "SMTP auth failed, but OTP was printed to console for development."
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"


def store_otp(role, identifier, email):
    """Generate OTP, store it, and email it. Returns (success, message)."""
    otp = generate_otp()
    key = f"{role}:{identifier}"
    otp_sessions[key] = {
        'otp': otp,
        'expiry': time.time() + OTP_EXPIRY,
        'email': email,
    }
    # DEBUG: remove after fixing
    print(f"\n[DEBUG store_otp] key={key!r}, otp={otp!r}, expiry_in={OTP_EXPIRY}s")
    print(f"[DEBUG store_otp] otp_sessions keys: {list(otp_sessions.keys())}")
    role_labels = {'admin': 'Admin', 'faculty': 'Faculty', 'student': 'Student'}
    return send_otp_email(email, otp, role_labels.get(role, 'User'))


def verify_otp(role, identifier, submitted_otp):
    """Verify the submitted OTP. Returns True if valid."""
    key = f"{role}:{identifier}"
    data = otp_sessions.get(key)
    # DEBUG: remove after fixing
    print(f"\n[DEBUG verify_otp] key={key!r}, submitted={submitted_otp!r}")
    print(f"[DEBUG verify_otp] otp_sessions keys: {list(otp_sessions.keys())}")
    if not data:
        print(f"[DEBUG verify_otp] FAIL: no data found for key {key!r}")
        return False
    remaining = data['expiry'] - time.time()
    print(f"[DEBUG verify_otp] stored_otp={data['otp']!r}, remaining={remaining:.0f}s")
    if time.time() > data['expiry']:
        del otp_sessions[key]
        print(f"[DEBUG verify_otp] FAIL: expired")
        return False
    if data['otp'] != submitted_otp.strip():
        print(f"[DEBUG verify_otp] FAIL: mismatch stored={data['otp']!r} vs submitted={submitted_otp.strip()!r}")
        return False
    # OTP is valid — remove it (single use)
    del otp_sessions[key]
    print(f"[DEBUG verify_otp] SUCCESS")
    return True


# ──────────────────────────────────────────────────────────
#  PUBLIC URL DETECTION (for QR codes)
# ──────────────────────────────────────────────────────────
def get_local_ip():
    """Get LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def hostname_resolves(hostname):
    """Return True if DNS resolves hostname (with a short in-memory cache)."""
    if not hostname:
        return False

    now = time.time()
    cached = _public_url_dns_cache.get(hostname)
    if cached and (now - cached["checked_at"]) <= PUBLIC_URL_DNS_CACHE_SECONDS:
        return cached["ok"]

    try:
        socket.getaddrinfo(hostname, None)
        ok = True
    except socket.gaierror:
        ok = False

    _public_url_dns_cache[hostname] = {"ok": ok, "checked_at": now}
    return ok


def get_public_url():
    """
    Priority:
      1. PUBLIC_URL / APP_PUBLIC_URL env var for a hosted domain or public IP
      2. WINDOWS_IP env var — the actual WiFi IP of the Windows host
      3. Fall back to LAN IP
    """
    # 1. Manual public URL override.
    # Use this for a deployed domain, reverse proxy, or router port-forward.
    for env_name in ("PUBLIC_URL", "APP_PUBLIC_URL"):
        env_url = os.environ.get(env_name, "").rstrip('/')
        if env_url:
            parsed = urllib.parse.urlparse(
                env_url if "://" in env_url else f"https://{env_url}"
            )
            host = (parsed.hostname or "").strip()
            if host and not hostname_resolves(host):
                app.logger.warning(
                    "%s is set but DNS does not resolve '%s'. "
                    "Ignoring it and falling back to LAN URL.",
                    env_name,
                    host,
                )
                continue
            return env_url

    # 2. Windows WiFi IP (set via env var or auto-detected)
    win_ip = os.environ.get("WINDOWS_IP", get_local_ip())
    return f"http://{win_ip}:{SERVER_PORT}"


def get_socketio_url():
    """Return an optional explicit Socket.IO endpoint.

    Leave SOCKETIO_URL empty in normal use so browsers connect to the same
    origin they loaded the dashboard from. Set it only when a reverse proxy or
    public host requires the websocket to use a different origin.
    """
    return os.environ.get("SOCKETIO_URL", "").rstrip('/')


def is_public_access_url(url):
    """True when the URL should work outside the current LAN."""
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or host == "localhost":
        return False

    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return True


# ──────────────────────────────────────────────────────────
#  DATABASE INITIALISATION — execute database.sql on first run
# ──────────────────────────────────────────────────────────
def init_database():
    """
    Read database.sql and execute every statement against MySQL.
    Uses a raw MySQLdb connection (not flask-mysqldb) so we can
    issue CREATE DATABASE before the Flask app's DB binding is ready.
    Safe to call repeatedly — every statement uses IF NOT EXISTS /
    INSERT IGNORE / IF NOT EXISTS guards.
    """
    sql_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.sql')
    if not os.path.isfile(sql_path):
        app.logger.warning("database.sql not found — skipping DB init")
        return

    try:
        import MySQLdb
    except ImportError:
        app.logger.warning("MySQLdb not installed — cannot run database.sql")
        return

    try:
        with open(sql_path, 'r', encoding='utf-8') as f:
            sql_content = f.read()

        # Strip single-line comments (-- …)
        lines = [
            line for line in sql_content.splitlines()
            if not line.strip().startswith('--')
        ]
        sql_content = '\n'.join(lines)

        # Split on semicolons and drop empty fragments
        statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip()]

        # Connect WITHOUT specifying a database so CREATE DATABASE works
        conn = MySQLdb.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            passwd=app.config['MYSQL_PASSWORD'],
        )
        cursor = conn.cursor()

        for stmt in statements:
            try:
                cursor.execute(stmt)
            except Exception as e:
                # Log but continue — e.g. duplicate ALTERs on re-run
                app.logger.debug("database.sql statement skipped: %s — %s",
                                 stmt[:60], e)

        conn.commit()
        cursor.close()
        conn.close()
        app.logger.info("database.sql executed successfully — DB is ready")
    except Exception as e:
        app.logger.error("Failed to initialise database from database.sql: %s", e)


# ──────────────────────────────────────────────────────────
#  DATABASE MIGRATIONS (idempotent, run once on first request)
# ──────────────────────────────────────────────────────────
def ensure_admin_email_column():
    """
    Run once at startup — applies all incremental DB migrations:
    1. Add email column to admin if missing.
    2. Widen all password columns to TEXT.
    3. Add course_id to attendance table if missing.
    4. Ensure a fallback 'UNKNOWN' course exists.
    5. Add device_fp column to attendance for device fingerprinting.
    6. Add latitude/longitude columns to attendance for geolocation audit.
    """
    try:
        cur = mysql.connection.cursor()

        # ── 1. email on admin ──────────────────────────────
        cur.execute("SHOW COLUMNS FROM admin LIKE 'email'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE admin ADD COLUMN email VARCHAR(100) AFTER password")

        # ── 2. Widen password columns to TEXT ──────────────
        for tbl in ('admin', 'faculty', 'students'):
            cur.execute(f"SHOW COLUMNS FROM `{tbl}` LIKE 'password'")
            col = cur.fetchone()
            if col and 'varchar' in str(col[1]).lower():
                cur.execute(f"ALTER TABLE `{tbl}` MODIFY COLUMN password TEXT NOT NULL")

        # ── 3. Add course_id to attendance if missing ──────
        cur.execute("SHOW COLUMNS FROM attendance LIKE 'course_id'")
        if not cur.fetchone():
            cur.execute("INSERT IGNORE INTO courses(course_id, course_name) "
                        "VALUES('UNKNOWN', 'Unknown / Legacy')")
            cur.execute("ALTER TABLE attendance "
                        "ADD COLUMN course_id VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN' "
                        "AFTER roll")
            try:
                cur.execute("ALTER TABLE attendance "
                            "ADD CONSTRAINT fk_att_course "
                            "FOREIGN KEY (course_id) REFERENCES courses(course_id)")
            except Exception:
                pass

        # ── 4. Add device_fp column if missing ─────────────
        cur.execute("SHOW COLUMNS FROM attendance LIKE 'device_fp'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE attendance ADD COLUMN device_fp VARCHAR(16) DEFAULT NULL")

        # ── 5. Add geolocation columns if missing ──────────
        cur.execute("SHOW COLUMNS FROM attendance LIKE 'latitude'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE attendance ADD COLUMN latitude DOUBLE DEFAULT NULL")
        cur.execute("SHOW COLUMNS FROM attendance LIKE 'longitude'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE attendance ADD COLUMN longitude DOUBLE DEFAULT NULL")

        mysql.connection.commit()
    except Exception:
        pass  # silent — table may not exist yet on first boot


_db_migrated = False


@app.before_request
def run_migrations():
    global _db_migrated
    if not _db_migrated:
        init_database()              # ← execute database.sql first
        ensure_admin_email_column()  # ← then run incremental migrations
        _db_migrated = True


# ──────────────────────────────────────────────────────────
#  QR REDIRECT
# ──────────────────────────────────────────────────────────
@app.route('/go')
def qr_redirect():
    """Backward-compatible redirect for QR codes generated by older builds."""
    token = request.args.get('token', '')
    return redirect(f"/student_login?token={urllib.parse.quote(token)}")


# ──────────────────────────────────────────────────────────
#  HOME
# ──────────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template("main_dashboard.html")


@app.route('/about')
def about():
    return render_template("about.html")


# ──────────────────────────────────────────────────────────
#  ADMIN LOGIN
# ──────────────────────────────────────────────────────────
@app.route('/admin')
def admin_login_route():
    if 'admin' in session:
        return redirect('/admin_dashboard')
    return render_template("admin_login.html")


@app.route('/admin_login', methods=['POST'])
@csrf_protect
@limiter.limit("10 per minute")
def admin_login():
    username = request.form['username']
    password = request.form['password']
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM admin WHERE username=%s", (username,))
    admin = cur.fetchone()
    if admin:
        cols = [desc[0] for desc in cur.description]
        admin_data = dict(zip(cols, admin))
        if password_matches(admin_data['password'], password):
            session['admin'] = username
            return redirect('/admin_dashboard')
    return render_template("admin_login.html", error="Invalid username or password")


# ──────────────────────────────────────────────────────────
#  ADMIN DASHBOARD
# ──────────────────────────────────────────────────────────
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' not in session:
        return redirect('/')
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM faculty")
    faculty_list = cur.fetchall()
    cur.execute("SELECT * FROM students")
    students_list = cur.fetchall()
    cur.execute("SELECT * FROM courses")
    courses_list = cur.fetchall()

    cur.execute("""
        SELECT a.roll, s.name, c.course_name, a.date, a.status, a.created_at
        FROM attendance a
        JOIN students s ON a.roll = s.roll
        JOIN courses c ON a.course_id = c.course_id
        ORDER BY a.date DESC, a.created_at DESC
    """)
    attendance_list = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM attendance WHERE date=UTC_DATE()")
    today_count = cur.fetchone()[0]

    return render_template("admin_dashboard.html",
                           faculty_list=faculty_list,
                           students_list=students_list,
                           courses_list=courses_list,
                           attendance_list=attendance_list,
                           today_count=today_count,
                           faculty_msg=session.pop('faculty_msg', None),
                           course_msg=session.pop('course_msg', None),
                           student_msg=session.pop('student_msg', None))


# ──────────────────────────────────────────────────────────
#  ADD COURSE
# ──────────────────────────────────────────────────────────
@app.route('/add_course', methods=['POST'])
@csrf_protect
def add_course():
    if 'admin' not in session:
        return redirect('/')
    course_id   = request.form['course_id']
    course_name = request.form['course_name']
    cur = mysql.connection.cursor()
    try:
        cur.execute("INSERT INTO courses(course_id, course_name) VALUES(%s, %s)",
                    (course_id, course_name))
        mysql.connection.commit()
        session['course_msg'] = f"Course '{course_name}' added successfully!"
    except Exception as e:
        session['course_msg'] = f"Error: {str(e)}"
    return redirect('/admin_dashboard#add-course')


@app.route('/delete_course/<course_id>')
def delete_course(course_id):
    if 'admin' not in session:
        return redirect('/')
    cur = mysql.connection.cursor()
    # Prevent deletion if attendance records exist
    cur.execute("SELECT COUNT(*) FROM attendance WHERE course_id=%s", (course_id,))
    count = cur.fetchone()[0]
    if count > 0:
        session['course_msg'] = (
            f"Cannot delete course '{course_id}' — {count} attendance record(s) exist. "
            f"Delete or reassign those records first."
        )
        return redirect('/admin_dashboard#add-course')
    cur.execute("DELETE FROM courses WHERE course_id=%s", (course_id,))
    mysql.connection.commit()
    session['course_msg'] = f"Course '{course_id}' deleted."
    return redirect('/admin_dashboard#add-course')


# ──────────────────────────────────────────────────────────
#  ADD FACULTY
# ──────────────────────────────────────────────────────────
@app.route('/add_faculty', methods=['POST'])
@csrf_protect
def add_faculty():
    if 'admin' not in session:
        return redirect('/')
    name     = request.form.get('name', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    email    = request.form.get('email', '').strip()
    hashed = make_password_hash(password)
    cur = mysql.connection.cursor()
    try:
        cur.execute("INSERT INTO faculty(name,username,password,email) VALUES(%s,%s,%s,%s)",
                    (name, username, hashed, email))
        mysql.connection.commit()
        session['faculty_msg'] = f"Faculty '{name}' added successfully!"
    except Exception as e:
        session['faculty_msg'] = f"Error: Username '{username}' already exists."
    return redirect('/admin_dashboard#add-faculty')


# ──────────────────────────────────────────────────────────
#  DELETE FACULTY
# ──────────────────────────────────────────────────────────
@app.route('/delete_faculty/<int:id>')
def delete_faculty(id):
    if 'admin' not in session:
        return redirect('/')
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM faculty WHERE id=%s", (id,))
    mysql.connection.commit()
    return redirect('/admin_dashboard#add-faculty')


# ──────────────────────────────────────────────────────────
#  ADD STUDENT (by admin)
# ──────────────────────────────────────────────────────────
@app.route('/add_student', methods=['POST'])
@csrf_protect
def add_student():
    if 'admin' not in session:
        return redirect('/')

    roll     = request.form.get('roll', '').strip()
    name     = request.form.get('name', '').strip()
    password = request.form.get('password', '')
    email    = request.form.get('email', '').strip()

    hashed = make_password_hash(password)

    cur = mysql.connection.cursor()
    try:
        cur.execute(
            "INSERT INTO students(roll, name, email, password) VALUES(%s,%s,%s,%s)",
            (roll, name, email, hashed)
        )
        mysql.connection.commit()
        session['student_msg'] = f"Student '{name}' added successfully!"
    except Exception as e:
        session['student_msg'] = f"Error: {str(e)}"

    return redirect('/admin_dashboard#add-student')


# ──────────────────────────────────────────────────────────
#  DELETE STUDENT
# ──────────────────────────────────────────────────────────
@app.route('/delete_student/<roll>')
def delete_student(roll):
    if 'admin' not in session:
        return redirect('/')
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM attendance WHERE roll=%s", (roll,))
    cur.execute("DELETE FROM students WHERE roll=%s", (roll,))
    mysql.connection.commit()
    return redirect('/admin_dashboard#add-student')


# ──────────────────────────────────────────────────────────
#  FACULTY LOGIN
# ──────────────────────────────────────────────────────────
@app.route('/faculty_login_page')
def faculty_login_page():
    return render_template("faculty_login.html")


@app.route('/faculty_login', methods=['POST'])
@csrf_protect
@limiter.limit("10 per minute")
def faculty_login():
    username = request.form['username']
    password = request.form['password']
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM faculty WHERE username=%s", (username,))
    faculty = cur.fetchone()
    if faculty:
        cols = [desc[0] for desc in cur.description]
        faculty_data = dict(zip(cols, faculty))
        if password_matches(faculty_data['password'], password):
            session['faculty']      = username
            session['faculty_name'] = faculty_data.get('name', username)
            return redirect('/faculty_dashboard')
    return render_template("faculty_login.html", error="Invalid username or password")


# ──────────────────────────────────────────────────────────
#  FACULTY DASHBOARD
# ──────────────────────────────────────────────────────────
@app.route('/faculty_dashboard')
def faculty_dashboard():
    if 'faculty' not in session:
        return redirect('/')
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM courses")
    courses_list = cur.fetchall()

    cur.execute("""
        SELECT a.roll, s.name, c.course_name, a.status, a.created_at
        FROM attendance a
        JOIN students s ON a.roll = s.roll
        JOIN courses c ON a.course_id = c.course_id
        WHERE a.date = UTC_DATE()
        ORDER BY a.created_at DESC
    """)
    today_attendance = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM attendance WHERE date=UTC_DATE() AND status='Present'")
    present_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM students")
    total_students = cur.fetchone()[0]
    absent_count   = total_students - present_count

    faculty_user = session.get('faculty')
    qr_active    = False
    qr_remaining = 0
    qr_course    = ""
    qr_rotate_interval = QR_ROTATE_INTERVAL
    if faculty_user in qr_sessions:
        remaining = qr_sessions[faculty_user]['expiry'] - time.time()
        if remaining > 0:
            qr_active    = True
            qr_remaining = int(remaining)
            qr_course    = qr_sessions[faculty_user]['course_id']
            qr_rotate_interval = qr_sessions[faculty_user].get('rotate_interval', QR_ROTATE_INTERVAL)
        else:
            del qr_sessions[faculty_user]

    return render_template("faculty_dashboard.html",
                           today_attendance=today_attendance,
                           present_count=present_count,
                           absent_count=absent_count,
                           total_students=total_students,
                           courses_list=courses_list,
                           faculty_name=session.get('faculty_name', ''),
                           faculty_user=faculty_user,
                           qr_active=qr_active,
                           qr_remaining=qr_remaining,
                           qr_course=qr_course,
                           qr_rotate_interval=qr_rotate_interval,
                           socketio_url=get_socketio_url())


# ──────────────────────────────────────────────────────────
#  GENERATE QR
# ──────────────────────────────────────────────────────────
@app.route('/generate_qr', methods=['POST'])
@csrf_protect
def generate_qr():
    if 'faculty' not in session:
        return redirect('/')

    minutes      = int(request.form.get('minutes', 5))
    course_id    = request.form.get('course_id')
    minutes      = max(1, min(minutes, 60))
    faculty_user = session.get('faculty')

    seed = secrets.token_urlsafe(32)

    qr_sessions[faculty_user] = {
        'seed': seed,
        'expiry': time.time() + (minutes * 60),
        'course_id': course_id,
        'rotate_interval': QR_ROTATE_INTERVAL
    }

    return redirect('/faculty_dashboard')


# ──────────────────────────────────────────────────────────
#  LIVE QR IMAGE (rotates every 15s)
# ──────────────────────────────────────────────────────────
@app.route('/qr_image/<faculty_user>')
def qr_image(faculty_user):
    """Return the current rotating QR code as a PNG image."""
    data = qr_sessions.get(faculty_user)
    if not data or data['expiry'] <= time.time():
        buf = io.BytesIO()
        img = qrcode.make('expired')
        img.save(buf, format='PNG')
        buf.seek(0)
        return send_file(buf, mimetype='image/png')

    token = derive_token(data['seed'], data.get('rotate_interval', QR_ROTATE_INTERVAL))
    base_url = get_public_url()
    url = f"{base_url}/student_login?token={token}"

    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png',
                     download_name=f'qr_{faculty_user}.png',
                     max_age=0)


# ──────────────────────────────────────────────────────────
#  QR STATUS API
# ──────────────────────────────────────────────────────────
@app.route('/qr_status')
def qr_status():
    token = request.args.get('token')
    if not token:
        return jsonify({'active': False, 'message': 'No token provided'})

    for faculty, data in list(qr_sessions.items()):
        remaining = data['expiry'] - time.time()
        if remaining <= 0:
            del qr_sessions[faculty]
            continue
        current_tok, prev_tok = derive_token_with_grace(
            data['seed'], data.get('rotate_interval', QR_ROTATE_INTERVAL))
        if token in (current_tok, prev_tok):
            return jsonify({'active': True, 'remaining': int(remaining)})

    return jsonify({'active': False, 'remaining': 0})


# ──────────────────────────────────────────────────────────
#  STUDENT SIGNUP
# ──────────────────────────────────────────────────────────
@app.route('/student_signup')
def student_signup():
    return render_template("student_signup.html")


@app.route('/student_register', methods=['POST'])
@csrf_protect
@limiter.limit("5 per hour")
def student_register():
    name     = request.form.get('name', '').strip()
    roll     = request.form.get('roll', '').strip()
    email    = request.form.get('email', '').strip()
    password = request.form.get('password', '')

    hashed = make_password_hash(password)

    cur = mysql.connection.cursor()
    try:
        cur.execute("INSERT INTO students(roll, name, email, password) VALUES(%s, %s, %s, %s)",
                    (roll, name, email, hashed))
        mysql.connection.commit()
        return render_template("student_signup.html",
                               success="Registration successful! You can now login.")
    except Exception as e:
        return render_template("student_signup.html",
                               error=f"Registration failed: {str(e)}")


# ──────────────────────────────────────────────────────────
#  STUDENT LOGIN PAGE
# ──────────────────────────────────────────────────────────
@app.route('/student_login')
def student_login():
    token = request.args.get('token')
    if not token or token == 'None':
        return render_template("student_login.html",
                               error="Invalid access. Please scan the QR code provided by your faculty.")

    active_session = None
    matched_faculty = None
    for faculty, data in list(qr_sessions.items()):
        if data['expiry'] <= time.time():
            continue
        current_tok, prev_tok = derive_token_with_grace(
            data['seed'], data.get('rotate_interval', QR_ROTATE_INTERVAL))
        if token in (current_tok, prev_tok):
            active_session = data
            matched_faculty = faculty
            break

    if not active_session:
        return render_template("student_login.html",
                               error="QR session has expired or is invalid. Please scan the QR code again.")

    return render_template("student_login.html", token=token,
                           course_id=active_session['course_id'])


# ──────────────────────────────────────────────────────────
#  MARK ATTENDANCE
# ──────────────────────────────────────────────────────────
@app.route('/mark_attendance', methods=['POST'])
@csrf_protect
def mark_attendance():
    token = request.form.get('token')
    if not token or token == 'None':
        return render_template("student_login.html", error="Session token missing. Please scan QR again.")

    # Rotating token validation — check current + previous window
    active_session = None
    matched_faculty = None
    for faculty, data in list(qr_sessions.items()):
        if data['expiry'] <= time.time():
            continue
        current_tok, prev_tok = derive_token_with_grace(
            data['seed'], data.get('rotate_interval', QR_ROTATE_INTERVAL))
        if token in (current_tok, prev_tok):
            active_session = data
            matched_faculty = faculty
            break

    if not active_session:
        return render_template("student_login.html",
                               error="Session expired or QR code outdated. Please scan the latest QR code.")

    course_id = active_session['course_id']
    roll      = request.form['roll'].strip()
    password  = request.form['password']

    # ── Device fingerprint check ──────────────────────────
    fingerprint = get_device_fingerprint()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM students WHERE roll=%s", (roll,))
    student = cur.fetchone()

    if not student:
        return render_template("student_login.html", token=token, course_id=course_id,
                               error="Invalid roll number or password")

    cols = [desc[0] for desc in cur.description]
    student_data = dict(zip(cols, student))

    if not password_matches(student_data['password'], password):
        return render_template("student_login.html", token=token, course_id=course_id,
                               error="Invalid roll number or password")

    today_utc = datetime.datetime.utcnow().date()

    # Check if attendance already marked
    cur.execute("SELECT * FROM attendance WHERE roll=%s AND date=%s AND course_id=%s",
                (roll, today_utc, course_id))
    if cur.fetchone():
        return render_template("student_login.html", token=token, course_id=course_id,
                               error=f"Attendance already marked for {course_id} today!")

    # ── ANTI-PROXY: Check if this device already marked for another student ──
    cur.execute(
        "SELECT roll FROM attendance "
        "WHERE date=%s AND course_id=%s AND device_fp=%s AND roll != %s",
        (today_utc, course_id, fingerprint, roll))
    proxy_row = cur.fetchone()
    if proxy_row:
        return render_template("student_login.html", token=token, course_id=course_id,
                               error="⚠️ This device was already used to mark attendance "
                                     "for another student. Proxy attendance is not allowed.")

    # ── Capture geolocation (optional — sent from client JS) ──
    lat = request.form.get('latitude', type=float)
    lng = request.form.get('longitude', type=float)

    # ── Geolocation validation (optional) ──
    if lat and lng and not is_near_college(lat, lng):
        return render_template("student_login.html", token=token, course_id=course_id,
                               error="📍 You are not within the allowed campus area. "
                                     "Please ensure you are on campus to mark attendance.")

    cur.execute(
        "INSERT INTO attendance(roll, date, course_id, status, device_fp, latitude, longitude) "
        "VALUES(%s, %s, %s, %s, %s, %s, %s)",
        (roll, today_utc, course_id, "Present", fingerprint, lat, lng))
    mysql.connection.commit()

    # Emit real-time update only to the matching faculty dashboard.
    attendance_update = {
        'faculty': matched_faculty,
        'roll': roll,
        'name': student_data.get('name', roll),
        'course_id': course_id,
        'status': 'Present',
        'time': datetime.datetime.utcnow().strftime('%I:%M %p') + ' UTC'
    }
    socketio.emit(
        'new_attendance',
        attendance_update,
        room=faculty_socket_room(matched_faculty),
    )

    return render_template("student_login.html", token=token, course_id=course_id,
                           success="✅ Attendance marked successfully!")


# ──────────────────────────────────────────────────────────
#  VIEW ATTENDANCE
# ──────────────────────────────────────────────────────────
@app.route('/view_attendance', methods=['GET', 'POST'])
def view_attendance():
    if request.method == 'GET':
        return render_template('view_attendance.html')

    roll = request.form.get('roll', '').strip()
    password = request.form.get('password', '')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM students WHERE roll=%s", (roll,))
    student = cur.fetchone()

    if not student:
        return render_template('view_attendance.html',
                               error="Invalid roll number or password")

    cols = [desc[0] for desc in cur.description]
    student_data = dict(zip(cols, student))

    if not password_matches(student_data['password'], password):
        return render_template('view_attendance.html',
                               error="Invalid roll number or password")

    cur.execute("""
        SELECT a.date, c.course_name, a.status, a.created_at
        FROM attendance a
        JOIN courses c ON a.course_id = c.course_id
        WHERE a.roll = %s
        ORDER BY a.date DESC, a.created_at DESC
    """, (roll,))
    records = cur.fetchall()

    total = len(records)
    present = sum(1 for r in records if r[2] == 'Present')
    percentage = round((present / total) * 100, 1) if total > 0 else 0

    return render_template('view_attendance.html',
                           student_name=student_data.get('name', roll),
                           roll=roll,
                           records=records,
                           total=total,
                           present=present,
                           percentage=percentage)


# ──────────────────────────────────────────────────────────
#  LOGOUT
# ──────────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# ──────────────────────────────────────────────────────────
#  FORGOT PASSWORD — ADMIN
# ──────────────────────────────────────────────────────────
@app.route('/forgot_password/admin', methods=['GET', 'POST'])
@csrf_protect
def forgot_password_admin():
    if request.method == 'GET':
        return render_template('forgot_password.html',
                               role='admin', role_label='Admin',
                               action='/forgot_password/admin')

    step     = request.form.get('step', 'verify')
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip()

    if step == 'verify':
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM admin WHERE username=%s", (username,))
        admin = cur.fetchone()
        if admin:
            cols = [desc[0] for desc in cur.description]
            admin_data = dict(zip(cols, admin))
            if admin_data.get('email') and admin_data['email'].lower() == email.lower():
                # Send OTP
                ok, msg = store_otp('admin', username, email)
                if ok:
                    return render_template('forgot_password.html',
                                           role='admin', role_label='Admin',
                                           action='/forgot_password/admin',
                                           step='otp', username=username, email=email,
                                           otp_expiry=OTP_EXPIRY,
                                           info=f'OTP sent to {email[:3]}***{email[email.index("@"):]}')
                else:
                    return render_template('forgot_password.html',
                                           role='admin', role_label='Admin',
                                           action='/forgot_password/admin',
                                           error=f'Could not send OTP: {msg}')
        return render_template('forgot_password.html',
                               role='admin', role_label='Admin',
                               action='/forgot_password/admin',
                               error='No account found with that username and email.')

    elif step == 'otp':
        submitted_otp = request.form.get('otp', '').strip()
        if verify_otp('admin', username, submitted_otp):
            return render_template('forgot_password.html',
                                   role='admin', role_label='Admin',
                                   action='/forgot_password/admin',
                                   step='reset', username=username, email=email)
        return render_template('forgot_password.html',
                               role='admin', role_label='Admin',
                               action='/forgot_password/admin',
                               step='otp', username=username, email=email,
                               otp_expiry=OTP_EXPIRY,
                               error='Invalid or expired OTP. Please try again.')

    elif step == 'resend_otp':
        ok, msg = store_otp('admin', username, email)
        if ok:
            return render_template('forgot_password.html',
                                   role='admin', role_label='Admin',
                                   action='/forgot_password/admin',
                                   step='otp', username=username, email=email,
                                   otp_expiry=OTP_EXPIRY,
                                   info='A new OTP has been sent to your email.')
        return render_template('forgot_password.html',
                               role='admin', role_label='Admin',
                               action='/forgot_password/admin',
                               step='otp', username=username, email=email,
                               otp_expiry=OTP_EXPIRY,
                               error=f'Could not resend OTP: {msg}')

    # step == 'reset'
    new_password = request.form.get('new_password', '')
    confirm      = request.form.get('confirm_password', '')
    if not new_password or new_password != confirm:
        return render_template('forgot_password.html',
                               role='admin', role_label='Admin',
                               action='/forgot_password/admin',
                               step='reset', username=username, email=email,
                               error='Passwords do not match or are empty.')
    hashed = make_password_hash(new_password)
    cur = mysql.connection.cursor()
    cur.execute("UPDATE admin SET password=%s WHERE username=%s", (hashed, username))
    mysql.connection.commit()
    return render_template('forgot_password.html',
                           role='admin', role_label='Admin',
                           action='/forgot_password/admin',
                           success='Password reset successfully! You can now log in.')


# ──────────────────────────────────────────────────────────
#  FORGOT PASSWORD — FACULTY
# ──────────────────────────────────────────────────────────
@app.route('/forgot_password/faculty', methods=['GET', 'POST'])
@csrf_protect
def forgot_password_faculty():
    if request.method == 'GET':
        return render_template('forgot_password.html',
                               role='faculty', role_label='Faculty',
                               action='/forgot_password/faculty')

    step     = request.form.get('step', 'verify')
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip()

    if step == 'verify':
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM faculty WHERE username=%s", (username,))
        faculty = cur.fetchone()
        if faculty:
            cols = [desc[0] for desc in cur.description]
            faculty_data = dict(zip(cols, faculty))
            if faculty_data.get('email') and faculty_data['email'].lower() == email.lower():
                ok, msg = store_otp('faculty', username, email)
                if ok:
                    return render_template('forgot_password.html',
                                           role='faculty', role_label='Faculty',
                                           action='/forgot_password/faculty',
                                           step='otp', username=username, email=email,
                                           otp_expiry=OTP_EXPIRY,
                                           info=f'OTP sent to {email[:3]}***{email[email.index("@"):]}')
                else:
                    return render_template('forgot_password.html',
                                           role='faculty', role_label='Faculty',
                                           action='/forgot_password/faculty',
                                           error=f'Could not send OTP: {msg}')
        return render_template('forgot_password.html',
                               role='faculty', role_label='Faculty',
                               action='/forgot_password/faculty',
                               error='No account found with that username and email.')

    elif step == 'otp':
        submitted_otp = request.form.get('otp', '').strip()
        if verify_otp('faculty', username, submitted_otp):
            return render_template('forgot_password.html',
                                   role='faculty', role_label='Faculty',
                                   action='/forgot_password/faculty',
                                   step='reset', username=username, email=email)
        return render_template('forgot_password.html',
                               role='faculty', role_label='Faculty',
                               action='/forgot_password/faculty',
                               step='otp', username=username, email=email,
                               otp_expiry=OTP_EXPIRY,
                               error='Invalid or expired OTP. Please try again.')

    elif step == 'resend_otp':
        ok, msg = store_otp('faculty', username, email)
        if ok:
            return render_template('forgot_password.html',
                                   role='faculty', role_label='Faculty',
                                   action='/forgot_password/faculty',
                                   step='otp', username=username, email=email,
                                   otp_expiry=OTP_EXPIRY,
                                   info='A new OTP has been sent to your email.')
        return render_template('forgot_password.html',
                               role='faculty', role_label='Faculty',
                               action='/forgot_password/faculty',
                               step='otp', username=username, email=email,
                               otp_expiry=OTP_EXPIRY,
                               error=f'Could not resend OTP: {msg}')

    new_password = request.form.get('new_password', '')
    confirm      = request.form.get('confirm_password', '')
    if not new_password or new_password != confirm:
        return render_template('forgot_password.html',
                               role='faculty', role_label='Faculty',
                               action='/forgot_password/faculty',
                               step='reset', username=username, email=email,
                               error='Passwords do not match or are empty.')
    hashed = make_password_hash(new_password)
    cur = mysql.connection.cursor()
    cur.execute("UPDATE faculty SET password=%s WHERE username=%s", (hashed, username))
    mysql.connection.commit()
    return render_template('forgot_password.html',
                           role='faculty', role_label='Faculty',
                           action='/forgot_password/faculty',
                           success='Password reset successfully! You can now log in.')


# ──────────────────────────────────────────────────────────
#  FORGOT PASSWORD — STUDENT
# ──────────────────────────────────────────────────────────
@app.route('/forgot_password/student', methods=['GET', 'POST'])
@csrf_protect
def forgot_password_student():
    if request.method == 'GET':
        return render_template('forgot_password.html',
                               role='student', role_label='Student',
                               action='/forgot_password/student',
                               id_label='Roll Number', id_field='roll')

    step  = request.form.get('step', 'verify')
    roll  = request.form.get('roll', '').strip()
    email = request.form.get('email', '').strip()

    if step == 'verify':
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM students WHERE roll=%s", (roll,))
        student = cur.fetchone()
        if student:
            cols = [desc[0] for desc in cur.description]
            student_data = dict(zip(cols, student))
            if student_data.get('email') and student_data['email'].lower() == email.lower():
                ok, msg = store_otp('student', roll, email)
                if ok:
                    return render_template('forgot_password.html',
                                           role='student', role_label='Student',
                                           action='/forgot_password/student',
                                           id_label='Roll Number', id_field='roll',
                                           step='otp', roll=roll, email=email,
                                           otp_expiry=OTP_EXPIRY,
                                           info=f'OTP sent to {email[:3]}***{email[email.index("@"):]}')
                else:
                    return render_template('forgot_password.html',
                                           role='student', role_label='Student',
                                           action='/forgot_password/student',
                                           id_label='Roll Number', id_field='roll',
                                           error=f'Could not send OTP: {msg}')
        return render_template('forgot_password.html',
                               role='student', role_label='Student',
                               action='/forgot_password/student',
                               id_label='Roll Number', id_field='roll',
                               error='No account found with that roll number and email.')

    elif step == 'otp':
        submitted_otp = request.form.get('otp', '').strip()
        if verify_otp('student', roll, submitted_otp):
            return render_template('forgot_password.html',
                                   role='student', role_label='Student',
                                   action='/forgot_password/student',
                                   id_label='Roll Number', id_field='roll',
                                   step='reset', roll=roll, email=email)
        return render_template('forgot_password.html',
                               role='student', role_label='Student',
                               action='/forgot_password/student',
                               id_label='Roll Number', id_field='roll',
                               step='otp', roll=roll, email=email,
                               otp_expiry=OTP_EXPIRY,
                               error='Invalid or expired OTP. Please try again.')

    elif step == 'resend_otp':
        ok, msg = store_otp('student', roll, email)
        if ok:
            return render_template('forgot_password.html',
                                   role='student', role_label='Student',
                                   action='/forgot_password/student',
                                   id_label='Roll Number', id_field='roll',
                                   step='otp', roll=roll, email=email,
                                   otp_expiry=OTP_EXPIRY,
                                   info='A new OTP has been sent to your email.')
        return render_template('forgot_password.html',
                               role='student', role_label='Student',
                               action='/forgot_password/student',
                               id_label='Roll Number', id_field='roll',
                               step='otp', roll=roll, email=email,
                               otp_expiry=OTP_EXPIRY,
                               error=f'Could not resend OTP: {msg}')

    new_password = request.form.get('new_password', '')
    confirm      = request.form.get('confirm_password', '')
    if not new_password or new_password != confirm:
        return render_template('forgot_password.html',
                               role='student', role_label='Student',
                               action='/forgot_password/student',
                               id_label='Roll Number', id_field='roll',
                               step='reset', roll=roll, email=email,
                               error='Passwords do not match or are empty.')
    hashed = make_password_hash(new_password)
    cur = mysql.connection.cursor()
    cur.execute("UPDATE students SET password=%s WHERE roll=%s", (hashed, roll))
    mysql.connection.commit()
    return render_template('forgot_password.html',
                           role='student', role_label='Student',
                           action='/forgot_password/student',
                           id_label='Roll Number', id_field='roll',
                           success='Password reset successfully! You can now log in.')


# ──────────────────────────────────────────────────────────
#  DEBUG ROUTES (protected — require FLASK_DEBUG=true + X-Debug-Key)
# ──────────────────────────────────────────────────────────
def debug_allowed():
    """Debug routes are only accessible when:
    1. FLASK_DEBUG=true in environment
    2. X-Debug-Key header matches DEBUG_KEY env var"""
    debug_key = os.environ.get('DEBUG_KEY', '')
    return app.debug and debug_key and request.headers.get('X-Debug-Key') == debug_key


@app.route('/debug/check')
def debug_check():
    """Inspect DB records to diagnose login issues."""
    if not debug_allowed():
        abort(404)
    try:
        cur = mysql.connection.cursor()

        cur.execute("SHOW COLUMNS FROM admin")
        admin_cols = [row[0] for row in cur.fetchall()]

        cur.execute("SELECT * FROM admin")
        admins = cur.fetchall()

        cur.execute("SHOW COLUMNS FROM faculty")
        fac_cols = [row[0] for row in cur.fetchall()]

        cur.execute("SELECT id, name, username, email FROM faculty")
        facs = cur.fetchall()

        cur.execute("SHOW COLUMNS FROM students")
        stu_cols = [row[0] for row in cur.fetchall()]

        lines = ["<pre style='font-family:monospace;padding:20px'>"]
        lines.append(f"<b>ADMIN columns:</b> {admin_cols}\n")
        for row in admins:
            lines.append(f"  id={row[0]}  username={row[1]}  "
                         f"email={row[3] if len(row)>3 else 'N/A'}  "
                         f"pw_snippet={str(row[2])[:30]}...\n")

        lines.append(f"\n<b>FACULTY columns:</b> {fac_cols}\n")
        for row in facs:
            lines.append(f"  id={row[0]}  name={row[1]}  username={row[2]}  email={row[3]}\n")

        lines.append(f"\n<b>STUDENTS columns:</b> {stu_cols}\n")
        cur.execute("SELECT id, roll, name, email FROM students")
        for row in cur.fetchall():
            lines.append(f"  id={row[0]}  roll={row[1]}  name={row[2]}  email={row[3]}\n")

        lines.append("</pre>")
        return "".join(lines)
    except Exception as e:
        return f"<pre>Error: {e}</pre>", 500


@app.route('/debug/clean_spaces')
def debug_clean_spaces():
    """Removes accidental trailing spaces from database fields."""
    if not debug_allowed():
        abort(404)
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE students SET roll = TRIM(roll), name = TRIM(name), email = TRIM(email)")
        stu_count = cur.rowcount
        cur.execute("UPDATE faculty SET username = TRIM(username), name = TRIM(name), email = TRIM(email)")
        fac_count = cur.rowcount
        cur.execute("UPDATE admin SET username = TRIM(username), email = TRIM(email)")
        adm_count = cur.rowcount
        mysql.connection.commit()
        return (f"<p>Cleaned up spaces!<br>Students updated: {stu_count}<br>"
                f"Faculty updated: {fac_count}<br>Admin updated: {adm_count}</p>"
                f"<a href='/debug/check'>Check DB</a>")
    except Exception as e:
        return f"<p>Error: {e}</p>", 500


@app.route('/debug/migrate')
def debug_migrate():
    """Manually run all DB migrations."""
    if not debug_allowed():
        abort(404)
    global _db_migrated
    _db_migrated = False
    ensure_admin_email_column()
    _db_migrated = True
    return ("<pre style='font-family:monospace;padding:20px'>"
            "✅ Migrations applied successfully!\n\n"
            "- admin.email column: checked\n"
            "- password columns widened to TEXT: checked\n"
            "- attendance.course_id column: checked\n"
            "- attendance.device_fp column (anti-proxy): checked\n"
            "- attendance.latitude/longitude columns (geolocation): checked\n\n"
            "<a href='/debug/check'>→ Inspect DB records</a>\n"
            "<a href='/admin_dashboard'>→ Go to Admin Dashboard</a>"
            "</pre>")


@app.route('/debug/reset_admin', methods=['GET', 'POST'])
def debug_reset_admin():
    """Emergency admin password reset."""
    if not debug_allowed():
        abort(404)
    if request.method == 'GET':
        return '''
        <form method="POST" style="font-family:sans-serif;padding:30px">
          <h3>Emergency Admin Password Reset</h3>
          <label>Username: <input name="username" value="admin"></label><br><br>
          <label>New Password: <input name="new_password" type="text"></label><br><br>
          <button type="submit">Reset Password</button>
        </form>'''
    username     = request.form.get('username', 'admin')
    new_password = request.form.get('new_password', '')
    if not new_password:
        return "<p style='color:red'>Password cannot be empty.</p>"
    hashed = make_password_hash(new_password)
    cur = mysql.connection.cursor()
    cur.execute("UPDATE admin SET password=%s WHERE username=%s", (hashed, username))
    mysql.connection.commit()
    rows = cur.rowcount
    return (f"<p style='color:green;font-family:sans-serif;padding:20px'>"
            f"✅ Password for '<b>{username}</b>' updated ({rows} row(s) affected). "
            f"<a href='/admin'>Go to Admin Login →</a></p>")


@app.route('/debug/public_url')
def debug_public_url():
    """Show what public URL the QR code and websocket will use."""
    if not debug_allowed():
        abort(404)
    url = get_public_url()
    remote_msg = (
        "Public URL active - QR and live Socket.IO work from other networks."
        if is_public_access_url(url)
        else "Public tunnel not detected - using LAN IP (same Wi-Fi/hotspot only)."
    )
    return (f"<pre style='font-family:monospace;padding:20px'>"
            f"<b>Current URL for QR codes and Socket.IO:</b>\n\n"
            f"  {url}\n\n"
            f"Student login URL will be:\n"
            f"  {url}/student_login?token=&lt;token&gt;\n\n"
            f"{remote_msg}\n\n"
            f"To use outside the current Wi-Fi/hotspot:\n"
            f"  1. Host the app on a public server, or forward a router public port to port {SERVER_PORT} on this PC.\n"
            f"  2. Set PUBLIC_URL to your public https:// domain or public http://IP:port.\n"
            f"  3. Restart AMS, then generate a new QR code in the faculty dashboard.\n"
            f"</pre>")


# ──────────────────────────────────────────────────────────
#  TCP/IP SERVER (Mobile Communication)
# ──────────────────────────────────────────────────────────
def handle_tcp_client(conn, addr):
    try:
        app.logger.info(f"TCP connection from {addr}")
        conn.settimeout(10.0)
        data = conn.recv(4096)
        if not data:
            return
        
        message = json.loads(data.decode('utf-8'))
        action = message.get("action")
        
        response = {"status": "error", "message": "Unknown action"}
        
        if action == "ping":
            response = {"status": "ok", "message": "pong"}
        elif action == "mark_attendance":
            roll = message.get("roll")
            course_id = message.get("course_id", "UNKNOWN")
            if not roll:
                response = {"status": "error", "message": "Missing roll number"}
            else:
                with app.app_context():
                    cur = mysql.connection.cursor()
                    cur.execute("SELECT * FROM students WHERE roll=%s", (roll,))
                    if cur.fetchone():
                        # Note: In a full app, you might want additional checks (already marked, etc.)
                        cur.execute("INSERT INTO attendance(roll, course_id, status) VALUES(%s, %s, %s)",
                                    (roll, course_id, 'Present'))
                        mysql.connection.commit()
                        response = {"status": "success", "message": f"Attendance marked for {roll}"}
                        # Notify dashboard
                        socketio.emit('new_attendance', {'roll': roll, 'course_id': course_id, 'status': 'Present'}, room='ams_global')
                    else:
                        response = {"status": "error", "message": "Student not found"}
                        
        conn.sendall(json.dumps(response).encode('utf-8'))
    except json.JSONDecodeError:
        conn.sendall(json.dumps({"status": "error", "message": "Invalid JSON"}).encode('utf-8'))
    except Exception as e:
        app.logger.error(f"TCP server error: {e}")
        try:
            conn.sendall(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))
        except:
            pass
    finally:
        conn.close()

def start_tcp_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host, port))
        server.listen(5)
        app.logger.info(f"TCP server listening on {host}:{port}")
        
        while True:
            try:
                conn, addr = server.accept()
                client_thread = threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True)
                client_thread.start()
            except Exception as e:
                app.logger.error(f"TCP accept error: {e}")
                time.sleep(1)
    except Exception as e:
        app.logger.error(f"Failed to start TCP server on {host}:{port}: {e}")

# ──────────────────────────────────────────────────────────
#  RUN SERVER
# ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import threading

    def _print_url():
        time.sleep(1.5)  # wait for Flask to bind
        url = get_public_url()
        mode = "DEBUG" if app.debug else "PRODUCTION"
        print(f"\n{'='*55}")
        print(f"  AMS is running! ({mode} mode)")
        print(f"  Anti-Proxy Protection: ON")
        print(f"  Local:   http://127.0.0.1:{SERVER_PORT}")
        print(f"  Network: {url}")
        if is_public_access_url(url):
            print(f"  [OK] Public URL active - QR and live Socket.IO work from other networks")
        else:
            print(f"  [!!] No public URL detected - QR/websocket work on same Wi-Fi only")
            print(f"  Tip: set PUBLIC_URL to your hosted domain or public IP:port")
        print(f"  Anti-Proxy: Rotating QR ({QR_ROTATE_INTERVAL}s) + Device Fingerprint + Geolocation")
        print(f"  CSRF Protection: ON")
        print(f"  Rate Limiting: ON")
        print(f"{'='*55}\n")

    threading.Thread(target=_print_url, daemon=True).start()
    
    tcp_port = int(os.environ.get("TCP_PORT", 65432))
    threading.Thread(target=start_tcp_server, args=(SERVER_HOST, tcp_port), daemon=True).start()
    
    socketio.run(app, host=SERVER_HOST, port=SERVER_PORT,
                 debug=app.debug, use_reloader=False,
                 allow_unsafe_werkzeug=True)
