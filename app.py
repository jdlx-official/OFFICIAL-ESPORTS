# ---------- Part 1/4 ----------  
# app.py - Part 1/4: imports, app init, config, DB & models

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from sqlalchemy import text
from flask import render_template
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from sqlalchemy.exc import IntegrityError
import os, secrets, time, uuid, hashlib
from werkzeug.utils import secure_filename
from datetime import datetime   # keep only 1
from decimal import Decimal, InvalidOperation
import logging
from logging.handlers import TimedRotatingFileHandler
import traceback
import threading
import time
from sqlalchemy import func
from apscheduler.schedulers.background import BackgroundScheduler
from threading import Thread
from functools import wraps
from flask import session, redirect, url_for, flash
from datetime import datetime, timedelta
import pytesseract
from PIL import Image
import re
# ---------- App init ----------
app = Flask(__name__)

# ---------- Secret Key ----------
if not os.path.exists("secret.key"):
    with open("secret.key", "w") as f:
        f.write(secrets.token_hex(16))

with open("secret.key", "r") as f:
    app.secret_key = f.read().strip()

csrf = CSRFProtect(app)
@app.route("/get_csrf")
def get_csrf():
    return generate_csrf()

# ---------- LOGGING ----------
log_dir = os.path.join(app.root_path, "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "app.log")

handler = TimedRotatingFileHandler(log_file, when="midnight", backupCount=14, encoding="utf-8")
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)

app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)
app.logger.info("Logging initialized")

# ---------- Mail config ----------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'officialesports.care@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD','mfwviucicjkyvndc')  # MUST be set in env
app.config['MAIL_DEFAULT_SENDER'] = ('OFFICIAL ESPORTS', 'officialesports.care@gmail.com')

mail = Mail(app)

# ---------- Serializer ----------
s = URLSafeTimedSerializer(app.secret_key)

# ---------- DB ----------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ============================
# ⭐ ONE-TIME DB FIX BLOCK ⭐
# ============================



# ---------- MODELS ----------

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(100))
    action = db.Column(db.String(200))
    tournament_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MatchResults(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'))
    kills = db.Column(db.Integer, default=0)
    rank = db.Column(db.Integer, default=0)
    screenshot = db.Column(db.String(200))
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    points = db.Column(db.Integer, default=0)   # <-- बस इतना ही

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Integer, default=0)
    transactions = db.relationship('Transaction', backref='wallet', cascade="all, delete-orphan")

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=True)
    amount = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), default='pending')
    payu_txnid = db.Column(db.String(100), nullable=True)
    txn_id = db.Column(db.String(100), nullable=True)
    payu_mode = db.Column(db.String(50), nullable=True)
    payu_bank_ref = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    mobilenumber = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    participations = db.relationship('Participation', backref='user', cascade="all, delete-orphan")
    wallets = db.relationship('Wallet', backref='user', cascade="all, delete-orphan")
    transactions = db.relationship('Transaction', backref='user', cascade="all, delete-orphan")

class Tournament(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    desc = db.Column(db.String(255))
    location = db.Column(db.String(100))
    date = db.Column(db.String(50))
    entry_fee = db.Column(db.String(50))
    prize_pool = db.Column(db.Integer)
    image = db.Column(db.String(100))
    max_players = db.Column(db.Integer)
    current_players = db.Column(db.Integer, default=0)
    participations = db.relationship('Participation', backref='tournament', cascade="all, delete-orphan")
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="upcoming")
    rules = db.Column(db.Text)
    notes = db.Column(db.Text)
    room_id = db.Column(db.String(50))
    room_password = db.Column(db.String(50))
    duration = db.Column(db.Integer, default=30)
    result_published = db.Column(db.Boolean, default=False)
    notified = db.Column(db.Boolean, default=False)
    map = db.Column(db.String(50))
    mode = db.Column(db.String(50))
    type = db.Column(db.String(50))
    max_teams = db.Column(db.Integer)
    game_name = db.Column(db.String(50))   # BGMI / FREE FIRE
    map_name = db.Column(db.String(50))    # Erangel / Livik / TDM
    mode = db.Column(db.String(20))        # solo / duo / squad
    game_type = db.Column(db.String(10))   # fpp / tpp
    match_link = db.Column(db.String(255), nullable=True)

    duration_minutes = db.Column(db.Integer)  # 60 / 30 / 20



class Participation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'))

    team_name = db.Column(db.String(120))
    captain_name = db.Column(db.String(120))
    captain_bgmi_id = db.Column(db.String(50))

    p2_name = db.Column(db.String(120))
    p2_id = db.Column(db.String(50))
    p3_name = db.Column(db.String(120))
    p3_id = db.Column(db.String(50))
    p4_name = db.Column(db.String(120))
    p4_id = db.Column(db.String(50))

    phone = db.Column(db.String(20))
    email = db.Column(db.String(100))

    status = db.Column(db.String(20), default="joined")
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)


class Ad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    desc = db.Column(db.String(255))
    image = db.Column(db.String(255))
    link = db.Column(db.String(255))
    image_url = db.Column(db.String(300))
    link_url = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)

class WithdrawRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    ifsc = db.Column(db.String(20), nullable=False)
    holder_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TournamentRegistration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'))

    team_name = db.Column(db.String(120))
    captain_name = db.Column(db.String(120))
    captain_email = db.Column(db.String(120))
    captain_bgmi_id = db.Column(db.String(50))

    p2_name = db.Column(db.String(120))
    p2_id = db.Column(db.String(50))
    p3_name = db.Column(db.String(120))
    p3_id = db.Column(db.String(50))
    p4_name = db.Column(db.String(120))
    p4_id = db.Column(db.String(50))

    mode = db.Column(db.String(20))
    map = db.Column(db.String(20))
    phone = db.Column(db.String(20))

    holder = db.Column(db.String(120))
    account_number = db.Column(db.String(120))
    ifsc = db.Column(db.String(20))


# ---------- Audit Log ----------
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def log_action(user_id, action):
    entry = AuditLog(user_id=user_id, action=action)
    db.session.add(entry)
    db.session.commit()




# ---------- APSCHEDULER ----------
scheduler = BackgroundScheduler()
scheduler.start()

def auto_fix_wallets():
    with app.app_context():
        wallets = Wallet.query.all()
        for w in wallets:
            if w.balance < 0:
                w.balance = 0
        db.session.commit()

def auto_fix_transactions():
    with app.app_context():
        tx = Transaction.query.filter(Transaction.amount == None).all()
        for t in tx:
            t.amount = "0"
        db.session.commit()

scheduler.add_job(auto_fix_wallets, "interval", minutes=30)
scheduler.add_job(auto_fix_transactions, "interval", minutes=60)




def get_current_user():
    """Return logged-in user object from session."""
    if 'username' not in session:
        return None
    return User.query.filter_by(username=session['username']).first()

@app.route("/whoami")
def whoami():
    user = get_current_user()
    if not user:
        return jsonify({"logged_in": False})
    return jsonify({
        "logged_in": True,
        "username": user.username,
        "email": user.email,
        "mobile": user.mobilenumber
    })
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Admin login required", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper

def user_already_joined(user_id, tournament_id):
    return Participation.query.filter_by(
        user_id=user_id,
        tournament_id=tournament_id
    ).first() is not None

def log_admin(action, tournament_id=None):
    admin_name = session.get("admin_username", "Unknown Admin")
    log = AdminLog(
        admin_name=admin_name,
        action=action,
        tournament_id=tournament_id
    )
    db.session.add(log)
    db.session.commit()




# ---------------- Admin Panel Setup ----------------
admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', url='/flask_admin')
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Ad, db.session, category="Advertisements"))
# ---------- Part 2/4 ----------
# app.py - Part 2/4: helpers, OLD payment endpoints, wallet helpers, signup/login/logout

# ---------- PayU config (OLD flow kept) ----------
PAYU_KEY = os.environ.get('PAYU_KEY', 'dnlpO5')
PAYU_SALT = os.environ.get('PAYU_SALT', 'CioAnb44qhh5GBWwfgqehk8tB3mgiCia')
PAYU_URL = "https://test.payu.in/_payment"   # test URL
app.config['PAYU_KEY'] = PAYU_KEY
app.config['PAYU_SALT'] = PAYU_SALT
app.config['PAYU_BASE_URL'] = PAYU_URL

# ---------------- Helper functions ----------------
def ensure_user_wallets():
    """Create Wallet rows for users that don't have one."""
    try:
        sub = db.session.query(Wallet.user_id)
        missing = db.session.query(User).filter(~User.id.in_(sub)).all()
        if missing:
            app.logger.info("Self-heal: creating wallets for %d users", len(missing))
            for u in missing:
                w = Wallet(user_id=u.id, balance=0)
                db.session.add(w)
            db.session.commit()
    except Exception as e:
        app.logger.error("ensure_user_wallets error: %s", str(e))


def reconcile_tournament_counts():
    """Make current_players reflect actual participations if mismatch found."""
    try:
        tournaments = Tournament.query.all()
        for t in tournaments:
            real_count = Participation.query.filter_by(tournament_id=t.id).count()
            if t.current_players != real_count:
                app.logger.info(f"Fixing tournament {t.id}: {t.current_players}→{real_count}")
                t.current_players = real_count
        db.session.commit()
    except Exception as e:
        app.logger.error("reconcile_tournament_counts error: %s", str(e))


def retry_failed_payments():
    """Retry failed callbacks (placeholder)."""
    try:
        # After you send payment model details, I'll complete this safely
        pass
    except Exception as e:
        app.logger.error("retry_failed_payments error: %s", str(e))


def get_or_create_wallet(user_id):
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if not wallet:
        wallet = Wallet(user_id=user_id, balance=0)
        db.session.add(wallet)
        db.session.commit()
    return wallet

def payu_hash_for_request(key, txnid, amount, productinfo, firstname, email, salt):
    seq = f"{key}|{txnid}|{amount}|{productinfo}|{firstname}|{email}|||||||||||{salt}"
    return hashlib.sha512(seq.encode('utf-8')).hexdigest().lower()

def payu_hash_verify_response(salt, status, key, txnid, amount, productinfo, firstname, email):
    seq = f"{salt}|{status}|||||||||||{email}|{firstname}|{productinfo}|{amount}|{txnid}|{key}"
    return hashlib.sha512(seq.encode('utf-8')).hexdigest().lower()

def extract_kills(text):
    import re
    match = re.search(r"Kills?\s*[:\-]?\s*(\d+)", text, re.IGNORECASE)
    return int(match.group(1)) if match else 0

def extract_rank(text):
    import re
    match = re.search(r"Rank\s*[:\-]?\s*(\d+)", text, re.IGNORECASE)
    return int(match.group(1)) if match else 0


# ---------------- ROUTES (OLD payment flow) ----------------
@app.route("/add_money", methods=["POST"])
def add_money():
    if 'username' not in session:
        return redirect(url_for("login"))

    raw_amount = request.form.get("amount")
    user = get_current_user()

    # Validate amount
    try:
        amt = Decimal(raw_amount)
        if amt <= 0:
            flash("Invalid amount!", "error")
            return redirect(url_for("wallet_add_page"))
        amount = str(int(amt))          # PayU only accepts integer string
    except:
        flash("Invalid amount!", "error")
        return redirect(url_for("wallet_add_page"))

    txn_id = "TXN" + str(int(time.time()))

    # PayU form data
    data = {
        "key": PAYU_KEY,
        "txnid": txn_id,
        "amount": amount,
        "productinfo": "Wallet Recharge",
        "firstname": user.username,
        "email": user.email,
        "phone": user.mobilenumber,
        "surl": url_for('payment_success', _external=True),
        "furl": url_for('payment_failed', _external=True),
    }

    # Correct Hash Format
    hash_string = f"{PAYU_KEY}|{txn_id}|{amount}|Wallet Recharge|{user.username}|{user.email}|||||||||||{PAYU_SALT}"
    hashh = hashlib.sha512(hash_string.encode()).hexdigest().lower()

    # store transaction
    t = Transaction(
        user_id=user.id,
        amount=amount,
        txn_id=txn_id,
        status="pending"
    )
    db.session.add(t)
    db.session.commit()

    # Auto redirect to PayU
    return f"""
        <html><body onload="document.payu.submit()">
        <form action="{PAYU_URL}" method="POST" name="payu">
            <input type="hidden" name="key" value="{PAYU_KEY}">
            <input type="hidden" name="txnid" value="{txn_id}">
            <input type="hidden" name="amount" value="{amount}">
            <input type="hidden" name="productinfo" value="Wallet Recharge">
            <input type="hidden" name="firstname" value="{user.username}">
            <input type="hidden" name="email" value="{user.email}">
            <input type="hidden" name="phone" value="{user.mobilenumber}">
            <input type="hidden" name="surl" value="{data['surl']}">
            <input type="hidden" name="furl" value="{data['furl']}">
            <input type="hidden" name="hash" value="{hashh}">
            <input type="hidden" name="service_provider" value="payu_paisa">
        </form>
        </body></html>
    """

    # Create a pending Transaction entry (legacy flow expects txn_id stored)
    #tx = Transaction(
    #   user_id=user.id,
    #    amount=amount_str,
    #    txn_id=txn_id,
    #    type="add_money",
    #    status="pending"
    #)
    #db.session.add(tx)
    #db.session.commit()

    #return render_template("payment_page.html", data=data, hashh=hashh, payu_url=PAYU_URL)

#payment success------
@app.route("/payment_success", methods=["GET", "POST"])
@csrf.exempt
def payment_success():
    user = get_current_user()
    if not user:
        flash("User not logged in", "error")
        return redirect(url_for("login"))

    amount = request.form.get("amount")
    txn_id = request.form.get("txnid")

    # Validate amount
    try:
        amt = Decimal(str(amount))
    except (InvalidOperation, TypeError):
        flash("Invalid amount in response", "error")
        return redirect(url_for("home"))

    # Update wallet
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    if not wallet:
        wallet = Wallet(user_id=user.id, balance=0)
        db.session.add(wallet)

    # Add integer rupees (existing code used int(float(amount)))
    wallet.balance += int(amt)

    # Record transaction — try to find by txn_id first
    t = Transaction.query.filter_by(txn_id=txn_id).first()
    if t:
        t.status = "success"
        t.amount = str(amount)
        t.user_id = user.id
    else:
        # fallback create record
        t = Transaction(
            user_id=user.id,
            amount=str(amount),
            txn_id=txn_id,
            status="success",
            type="add_money"
        )
        db.session.add(t)

    db.session.commit()

    flash("✅ Payment Successful! Amount added to wallet.", "success")
    return redirect(url_for("payment_success"))

#payment failed ----
@app.route("/payment_failed", methods=["GET", "POST"])
@csrf.exempt
def payment_failed():
    user = get_current_user()
    if not user:
        # If user not in session, still try to log transaction from POST (if txnid present)
        txn_id = request.form.get("txnid")
        amount = request.form.get("amount")
        t = Transaction.query.filter_by(txn_id=txn_id).first()
        if t:
            t.status = "failed"
            db.session.commit()
        flash("❌ Payment Failed!", "error")
        return redirect(url_for("login"))

    txn_id = request.form.get("txnid")
    amount = request.form.get("amount")

    t = Transaction.query.filter_by(txn_id=txn_id).first()
    if t:
        t.status = "failed"
        t.amount = str(amount) if amount is not None else t.amount
    else:
        t = Transaction(
            user_id=user.id,
            amount=str(amount) if amount is not None else "0",
            txn_id=txn_id,
            status="failed",
            type="add_money"
        )
        db.session.add(t)

    db.session.commit()

    flash("❌ Payment Failed!", "error")
    return redirect(url_for("home"))

# Wallet add page (simple amount input)
@app.route("/wallet/add", methods=["GET"])
def wallet_add_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("wallet_add.html")

# Wallet page (shows wallet & transactions)
@app.route("/wallet")
def wallet_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first_or_404()
    wallet = get_or_create_wallet(user.id)
    # Latest first
    txs = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.created_at.desc()).all()
    return render_template("wallet.html", wallet=wallet, txs=txs, user=user)

# ---------------- Signup ----------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        mobilenumber = request.form['mobilenumber']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('signup'))

        if len(password) < 8:
            flash("Password must be at least 8 characters long!", "error")
            return redirect(url_for('signup'))

        existing_user = User.query.filter(
            (User.username == username) |
            (User.email == email) |
            (User.mobilenumber == mobilenumber)
        ).first()

        if existing_user:
            flash("This username/email/phone is already registered! Please login.", "error")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, mobilenumber=mobilenumber, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("New user joined successfully.", "success")
        return redirect(url_for('login'))

    return render_template("signup.html")

# ---------------- Login ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_input = request.form['username']
        password = request.form['password']

        user = None
        if "@" in user_input:
            user = User.query.filter_by(email=user_input).first()
        elif user_input.isdigit():
            user = User.query.filter_by(mobilenumber=user_input).first()
        else:
            user = User.query.filter_by(username=user_input).first()

        if user and check_password_hash(user.password, password):
            user.is_active = True
            db.session.commit()
            session['username'] = user.username
            session['email'] = user.email
            session['mobilenumber'] = user.mobilenumber
            flash("✅ Login successful!", "success")
            return redirect(url_for('home_logged'))
        else:
            flash("❌ Invalid ID or Password. Please try again.", "error")
            return redirect(url_for('login'))

    return render_template("login.html")

# ---------------- Logout ----------------
@app.route('/logout', methods=["GET", "POST"])
def logout():
    user = get_current_user()
    if user:
        user.is_active = False
        db.session.commit()
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))
# ---------- Part 3/4 ----------
# app.py - Part 3/4: home, admin, tournaments, updater, CRUDs, ads, profile

# Home (logged / public)
@app.route('/home')
def home_logged():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_current_user()

    tournaments = Tournament.query.all()

    for t in tournaments:
        # joined flag
        t.joined = Participation.query.filter_by(
            user_id=user.id,
            tournament_id=t.id
        ).first() is not None

        # JS timer ke liye
        if t.start_time:
            t.start_ts = int(t.start_time.timestamp() * 1000)
            t.end_ts = int((t.start_time + timedelta(minutes=t.duration or 30)).timestamp() * 1000)

    wallet = get_or_create_wallet(user.id)
    transactions = Transaction.query.filter_by(
        user_id=user.id
    ).order_by(Transaction.created_at.desc()).all()

    ongoing = [t for t in tournaments if t.status == "ongoing"]
    upcoming = [t for t in tournaments if t.status == "upcoming"]
    finished = [t for t in tournaments if t.status == "completed"]

    return render_template(
        "home.html",
        user=user,
        username=user.username,
        email=user.email,
        tournaments=tournaments,
        ongoing=ongoing,
        upcoming=upcoming,
        finished=finished,
        wallet=wallet,
        transactions=transactions
    )


# User requests withdraw -> create WithdrawRequest (do NOT deduct balance yet)
@app.route("/withdraw_request", methods=["POST"])
def withdraw_request():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    try:
        amount = int(request.form.get("amount"))
    except (TypeError, ValueError):
        flash("❌ Invalid amount!", "error")
        return redirect(url_for("home"))

    account_number = request.form.get("account_number")
    ifsc = request.form.get("ifsc")
    holder_name = request.form.get("holder_name")
    upi = request.form.get("upi")

    wallet = get_or_create_wallet(user.id)

    # Check balance
    if wallet.balance < amount:
        flash("❌ Insufficient balance!", "error")
        return redirect(url_for("home"))

    # Create withdraw request with status pending. Do NOT deduct now.
    req = WithdrawRequest(
        user_id=user.id,
        amount=amount,
        account_number=account_number,
        ifsc=ifsc,
        holder_name=holder_name,
        status="pending",
        created_at=datetime.utcnow()
    )
    db.session.add(req)
    db.session.commit()

    flash("✅ Withdraw request submitted! Admin will review it.", "success")
    return redirect(url_for("home"))

@app.route("/admin/withdraws")
@admin_required
def view_withdraws():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    withdraws = WithdrawRequest.query.order_by(WithdrawRequest.id.desc()).all()
    return render_template("admin.html", withdraws=withdraws)

# Admin: view withdraws (already present)
# Approve a withdraw -> deduct wallet, create transaction, mark request approved
@app.route("/admin/withdraw_approve/<int:id>")
@admin_required
def withdraw_approve(id):
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    req = WithdrawRequest.query.get_or_404(id)

    if req.status != "pending":
        flash("This withdraw request is already processed.", "info")
        return redirect(url_for("view_withdraws"))

    wallet = Wallet.query.filter_by(user_id=req.user_id).first()
    if not wallet or wallet.balance < req.amount:
        flash("❌ User has insufficient balance to approve this withdraw.", "error")
        return redirect(url_for("view_withdraws"))

    # Deduct now
    wallet.balance -= req.amount

    # Transaction record
    t = Transaction(
        user_id=req.user_id,
        amount=str(req.amount),
        txn_id="WD" + str(req.id),
        status="success",
        type="withdraw",
        created_at=datetime.utcnow()
    )

    req.status = "approved"
    db.session.add(t)
    db.session.commit()

    flash("Withdraw Approved!", "success")
    return redirect(url_for("view_withdraws"))


# Reject withdraw -> mark rejected (no deduction), optionally notify user
@app.route("/admin/withdraw_reject/<int:id>")
@admin_required
def withdraw_reject(id):
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    req = WithdrawRequest.query.get_or_404(id)
    if req.status != "pending":
        flash("This withdraw request is already processed.", "info")
        return redirect(url_for("view_withdraws"))

    req.status = "rejected"
    db.session.commit()

    flash("Withdraw Rejected!", "info")
    return redirect(url_for("view_withdraws"))





@app.route('/')
def home():
    try:
        ads_data = Ad.query.filter_by(is_active=True).all()
    except Exception as e:
        ads_data = []
        print("⚠️ Warning: Ad table error:", e)

    try:
        tournaments = Tournament.query.all()

        # 🔹 ADD timestamps for JS (DO NOT REMOVE)
        now = datetime.utcnow()

        for t in tournaments:
            if not t.start_time:
                t.status = "upcoming"
                t.start_ts = 0
                t.end_ts = 0
                continue

            duration = t.duration_minutes or 60
            end_time = t.start_time + timedelta(minutes=duration)

            if t.start_time <= now <= end_time:
                t.status = "ongoing"
            elif now > end_time:
                t.status = "completed"
            else:
                t.status = "upcoming"

            t.start_ts = int(t.start_time.timestamp()) if t.start_time else 0
            t.end_ts = int(end_time.timestamp()) if end_time else 0

        # 🔹 tournament status lists
        ongoing = [t for t in tournaments if getattr(t, 'status', '') == 'ongoing']
        upcoming = [t for t in tournaments if getattr(t, 'status', '') == 'upcoming']
        finished = [t for t in tournaments if getattr(t, 'status', '') == 'completed']

    except Exception as e:
        tournaments = []
        ongoing = []
        upcoming = []
        finished = []
        print("⚠️ Warning: Tournament table error:", e)

    page_type = 'home'

    # 🔹 logged-in user
    if 'username' in session:
        return render_template(
            'home.html',
            user=get_current_user(),
            username=session['username'],
            email=session.get('email'),
            ads=ads_data,
            tournaments=tournaments,
            ongoing=ongoing,
            upcoming=upcoming,
            finished=finished,
            page_type=page_type
        )

    # 🔹 guest user
    return render_template(
        'home.html',
        user=None,
        ads=ads_data,
        tournaments=tournaments,
        ongoing=ongoing,
        upcoming=upcoming,
        finished=finished,
        page_type=page_type
    )


# 🔹 Search user (API)
@app.route("/search_user")
def search_user():
    query = request.args.get("q", "").strip()

    if not query:
        return jsonify([])

    users = User.query.filter(
        (User.username.ilike(f"%{query}%")) |
        (User.email.ilike(f"%{query}%")) |
        (User.mobilenumber.ilike(f"%{query}%"))
    ).all()

    result = [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "mobilenumber": user.mobilenumber
        }
        for user in users
    ]

    return jsonify(result)


@app.route("/upload_result", methods=["POST"])
def upload_result():
    user = get_current_user()
    tid = request.form.get("tournament_id")
    file = request.files.get("screenshot")

    if not file:
        flash("No screenshot uploaded!", "error")
        return redirect(request.referrer)

    filename = f"{user.id}_{tid}_{int(time.time())}.jpg"
    path = os.path.join("static/results", filename)
    file.save(path)

    # ---------- OCR ----------
    

    text = pytesseract.image_to_string(Image.open(path))

    kills = extract_kills(text)
    rank = extract_rank(text)

    result = MatchResults(
        user_id=user.id,
        tournament_id=tid,
        kills=kills,
        rank=rank,
        screenshot=filename,
        verified=False
    )
    db.session.add(result)
    db.session.commit()

    flash("Result submitted! Wait for admin review.", "success")
    return redirect(f"/admin/tournament/{tid}")

# Admin routes
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'jaydevlaxmi')

@app.route("/admin_login", methods=["GET","POST"])

def admin_login():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        if username==ADMIN_USERNAME and password==ADMIN_PASSWORD:
            session["admin_logged_in"]=True
            return redirect(url_for("admin_panel"))
        else:
            flash("Invalid admin credentials","error")
            return redirect(url_for("admin_login"))
    return render_template("admin_login.html")

from PIL import Image
import os

def compress_image(image_path, max_width=1200, quality=70):
    try:
        img = Image.open(image_path)

        # Resize if width is bigger
        if img.width > max_width:
            ratio = max_width / img.width
            new_height = int(img.height * ratio)
            img = img.resize((max_width, new_height), Image.LANCZOS)

        # Save compressed version
        img.save(image_path, optimize=True, quality=quality)

        print("✔ Image compressed:", image_path)
    except Exception as e:
        print("❌ Image compression failed:", e)


@app.route("/admin", methods=["GET","POST"])
@admin_required
def admin_panel():
    
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    
    results = MatchResults.query.order_by(MatchResults.id.desc()).all()

    search_query = request.args.get("search", "").strip()

    if search_query:
        users_data = User.query.filter(
            (User.username.ilike(f"%{search_query}%")) |
            (User.email.ilike(f"%{search_query}%")) |
            (User.mobilenumber.ilike(f"%{search_query}%"))
        ).all()
    else:
        users_data = User.query.all()

    tournaments_data = Tournament.query.all()
    try:
        ads_data = Ad.query.all()
        total_ads = Ad.query.count()
    except Exception as e:
        ads_data = []
        total_ads = 0
        print("⚠️ Warning: Ad table not found or error:", e)

    # ⭐⭐⭐ FIX: Withdraw Requests Load ⭐⭐⭐
    try:
        withdraws = WithdrawRequest.query.all()
    except:
        withdraws = []

    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    inactive_users = total_users - active_users
    total_tournaments = Tournament.query.count()
    current_online = active_users

    return render_template(
        "admin.html",
        users=users_data,
        withdraws=withdraws,
        results=results,
        tournaments=tournaments_data,
        ads=ads_data,
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        total_tournaments=total_tournaments,
        total_ads=total_ads,
        current_online=current_online,
        search_query=search_query
    )


# User CRUD
@app.route("/delete_user/<int:id>", methods=["GET","POST"])
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} deleted","success")
    return redirect(url_for("admin_panel"))

@app.route("/edit_user/<int:id>", methods=["POST"])
def edit_user(id):
    user = User.query.get_or_404(id)
    user.username = request.form["username"]
    user.email = request.form["email"]
    user.mobilenumber = request.form["mobilenumber"]
    # store hashed password if supplied (avoid storing plaintext unintentionally)
    new_password = request.form.get("password", "").strip()
    if new_password:
        user.password = generate_password_hash(new_password)
    db.session.commit()
    flash(f"User {user.username} updated","success")
    return redirect(url_for("admin_panel"))

@app.route("/add_user", methods=["POST"])
def add_user():
    username = request.form["username"]
    email = request.form["email"]
    mobilenumber = request.form["mobilenumber"]
    password = request.form["password"]
    hashed = generate_password_hash(password)
    new_user = User(username=username,email=email,mobilenumber=mobilenumber,password=hashed)
    db.session.add(new_user)
    db.session.commit()
    flash(f"User {username} added","success")
    return redirect(url_for("admin_panel"))

# Tournaments listings & routes
@app.route("/tournaments")
def tournaments():
    upcoming = Tournament.query.filter_by(status="upcoming").all()
    ongoing = Tournament.query.filter_by(status="ongoing").all()
    finished = Tournament.query.filter_by(status="finished").all()
    return render_template(
        "tournaments.html",
        upcoming=upcoming,
        ongoing=ongoing,
        finished=finished
    )

@app.route("/admin/tournament/<int:id>")
@admin_required
def tournament_detail(id):
    t = Tournament.query.get_or_404(id)

    participants = Participation.query.filter_by(tournament_id=id).all()
    results = MatchResults.query.filter_by(tournament_id=id).all()

    # Prepare user info for fast access
    users_dict = {}
    for p in participants:
        u = User.query.get(p.user_id)
        users_dict[p.user_id] = u

    return render_template("admin_tournament_detail.html",
                           t=t,
                           participants=participants,
                           results=results,
                           users_dict=users_dict,
                           registrations=participants)

@app.route("/tournament_register/<int:t_id>", methods=["GET"])
def tournament_register(t_id):
    t = Tournament.query.get_or_404(t_id)
    return render_template("registration.html", tournament=t)

@app.route("/tournament_register/<int:t_id>", methods=["POST"])
def submit_registration(t_id):
    t = Tournament.query.get_or_404(t_id)
    
    user = get_current_user()
    if not user:
        flash("Please login first!")
        return redirect(url_for("login"))

    p = Participation(
        user_id=user.id,
        tournament_id=t_id,
        username=request.form.get("teamName"),
        bgmi_id=request.form.get("capID"),
        email=request.form.get("email"),
        phone=request.form.get("phone"),
        status="joined"
    )
    data = {
        "team_name": request.form.get("teamName"),
        "captain_name": request.form.get("capName"),
        "captain_email": request.form.get("capEmail"),
        "captain_bgmi_id": request.form.get("capID"),
        "p2_name": request.form.get("p2Name"),
        "p2_id": request.form.get("p2ID"),
        "p3_name": request.form.get("p3Name"),
        "p3_id": request.form.get("p3ID"),
        "p4_name": request.form.get("p4Name"),
        "p4_id": request.form.get("p4ID"),
        "mode": request.form.get("mode"),
        "map": request.form.get("map"),
        "phone": request.form.get("phone"),
        "holder": request.form.get("holder"),
        "account_number": request.form.get("accNum"),
        "ifsc": request.form.get("ifsc"),
        "tournament_id": t_id
    }

    reg = TournamentRegistration(**data)
    db.session.add(reg)
    db.session.commit()

    flash("Registration completed!", "success")
    return redirect(url_for("home_logged"))

@app.route("/admin/finish_tournament/<int:id>")
@admin_required
def finish_tournament(id):
    t = Tournament.query.get(id)
    t.status = "completed"
    db.session.commit()

    # SEND MAIL TO ALL PARTICIPANTS
    participants = Participation.query.filter_by(tournament_id=id).all()

    for p in participants:
        send_mail(p.email, f"Tournament {t.name} results are ready!")

    flash("Tournament marked as completed & notifications sent!")
    return redirect(url_for("admin_panel"))

def send_mail(to, msg_text):
    import smtplib
    from email.mime.text import MIMEText

    msg = MIMEText(msg_text)
    msg["Subject"] = "Tournament Update"

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login("YOUR EMAIL", "YOUR APP PASSWORD")
    server.sendmail("YOUR EMAIL", to, msg.as_string())
    server.quit()


@app.route("/upload_match_result", methods=["POST"])
def upload_match_result():
    p_id = request.form.get("participation_id")
    p = Participation.query.get(p_id)

    file = request.files.get("screenshot")
    if file:
        filename = str(int(time.time())) + "_" + file.filename
        file.save("static/results/" + filename)
        p.screenshot = filename
        p.status = "submitted"

    db.session.commit()
    flash("Screenshot Uploaded!")
    return redirect(url_for("home_logged"))


@app.route("/admin/update_room/<int:id>", methods=["POST"])
@admin_required
def update_room(id):
    t = Tournament.query.get_or_404(id)

    if t.status not in ["upcoming", "ongoing"]:
        flash("Room details can only be updated before or during the match.", "error")
        return redirect(url_for("tournament_detail", id=id))

    old_room_id = t.room_id
    old_room_pass = t.room_password

    t.room_id = request.form.get("room_id")
    t.room_password = request.form.get("room_password")
    db.session.commit()

    # Log only room update
    log_admin(f"Updated room details (Old: {old_room_id}/{old_room_pass}) → (New: {t.room_id}/{t.room_password})", t.id)

    flash("Room details updated successfully!", "success")
    return redirect(url_for("tournament_detail", id=id))



# Tournament join/delete/edit/add
@app.route('/join_tournament/<int:tournament_id>', methods=['POST'])
def join_tournament(tournament_id):

    # 🔐 Login check
    user = get_current_user()
    if not user:
        flash("Please login to join the tournament.", "error")
        return redirect(url_for('login'))

    # 🎮 Tournament check
    tournament = Tournament.query.get_or_404(tournament_id)

    # ❌ Already joined check (covers both tables)
    existing_participation = Participation.query.filter_by(
        user_id=user.id,
        tournament_id=tournament.id
    ).first()

    existing_join = TournamentJoin.query.filter_by(
        user_id=user.id,
        tournament_id=tournament.id
    ).first()

    if existing_participation or existing_join:
        flash("You have already joined this tournament.", "info")
        return redirect(url_for('home'))

    # ❌ Max players limit check
    if tournament.max_players and tournament.current_players >= tournament.max_players:
        flash("Tournament is already full!", "error")
        return redirect(url_for('home'))

    # 💰 Entry fee
    entry_fee = int(tournament.entry_fee or 0)

    # ❌ Wallet balance check
    if user.wallet.balance < entry_fee:
        flash("Insufficient wallet balance", "error")
        return redirect(url_for('walletpage'))

    # =========================
    # 💰 ENTRY FEE AUTO DEDUCT
    # =========================
    user.wallet.balance -= entry_fee

    txn = Transaction(
        user_id=user.id,
        amount=entry_fee,
        type="entry_fee",
        status="success"
    )

    # 👤 Join records (both systems preserved)
    participation = Participation(
        user_id=user.id,
        tournament_id=tournament.id,
        status='joined'
    )

    join = TournamentJoin(
        user_id=user.id,
        tournament_id=tournament.id
    )

    # 🔢 Update players count safely
    tournament.current_players = (tournament.current_players or 0) + 1

    db.session.add(txn)
    db.session.add(participation)
    db.session.add(join)
    db.session.commit()

    flash("Joined tournament successfully!", "success")
    return redirect(url_for('home'))



@app.route("/delete_tournament/<int:id>", methods=["GET","POST"])
def delete_tournament(id):
    t = Tournament.query.get_or_404(id)
    db.session.delete(t)
    db.session.commit()
    flash(f"Tournament {t.name} deleted","success")
    return redirect(url_for("admin_panel"))


@app.route("/edit_tournament/<int:id>", methods=["POST"])
def edit_tournament(id):
    t = Tournament.query.get_or_404(id)

    t.name = request.form["name"]
    t.location = request.form["location"]
    t.date = request.form["date"]
    t.entry_fee = request.form["entry_fee"]
    t.prize_pool = request.form["prize_pool"]

    image_file = request.files.get("image")

    if image_file and image_file.filename:
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)

        # ⭐ AUTO COMPRESS IMAGE
        compress_image(image_path)

        t.image = filename

    db.session.commit()
    flash(f"Tournament {t.name} updated", "success")
    return redirect(url_for("admin_panel"))


# Upload folder for tournament images
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/add_tournament", methods=["POST"])
def add_tournament():

    game_name = request.form.get("game_name")
    map_name = request.form.get("map_name")
    mode = request.form.get("mode")

    # validation
    if not game_name or not map_name or not mode:
        flash("Game, Map and Mode are required", "error")
        return redirect(url_for("admin.index"))  # ✅ FIX HERE

    tournament_name = f"{game_name} | {mode.upper()} | {map_name}"

    start_time_raw = request.form.get("start_time")
    start_time = datetime.strptime(start_time_raw, "%Y-%m-%dT%H:%M")

    tournament = Tournament(
        name=tournament_name,
        desc=request.form.get("desc"),
        game_name=game_name,
        map=map_name,
        mode=mode,
        entry_fee=request.form.get("entry_fee"),
        prize_pool=request.form.get("prize_pool"),
        max_players=request.form.get("max_players"),
        start_time=start_time,
        image=request.form.get("image"),
        current_players=0,
        status="upcoming"
    )

    db.session.add(tournament)
    db.session.commit()

    flash("Tournament added successfully", "success")
    return redirect(url_for("admin.index"))  # ✅ FIX HERE



def auto_update_tournament_status():
    now = datetime.utcnow()
    tournaments = Tournament.query.all()

    for t in tournaments:
        if not t.start_time:
            continue

        duration = t.duration or 30
        start = t.start_time
        end = start + timedelta(minutes=duration)

        if t.status == "upcoming" and start <= now < end:
            t.status = "ongoing"

        elif t.status == "ongoing" and now >= end:
            t.status = "completed"

    db.session.commit()



@app.before_request
def before_request_func():
    auto_update_tournament_status()

@app.route("/upload_screenshot", methods=["POST"])
def upload_screenshot():
    user = get_current_user()
    if not user:
        flash("Login required to upload screenshot.", "error")
        return redirect(url_for("login"))

    t_id = int(request.form.get("tournament_id"))
    t = Tournament.query.get_or_404(t_id)

    # ✅ 1. User joined check
    participation = Participation.query.filter_by(
        user_id=user.id, tournament_id=t_id
    ).first()

    if not participation:
        flash("You are not a participant of this tournament.", "error")
        return redirect(url_for("home_logged"))

    # ✅ 2. Tournament status check
    if t.status not in ["ongoing", "completed"]:
        flash("You can only upload screenshot for ongoing/completed tournaments.", "error")
        return redirect(url_for("home_logged"))

    # ✅ 3. Already uploaded check
    existing = MatchResults.query.filter_by(
        user_id=user.id, tournament_id=t_id
    ).first()

    if existing:
        flash("You have already uploaded a result screenshot.", "info")
        return redirect(url_for("home_logged"))

    file = request.files.get("screenshot")
    if not file or not file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("home_logged"))

    filename = f"{int(time.time())}_{secure_filename(file.filename)}"
    save_path = os.path.join(app.root_path, "static", "results", filename)
    file.save(save_path)

    result = MatchResults(
        user_id=user.id,
        tournament_id=t_id,
        screenshot=filename,
        verified=False
    )

    db.session.add(result)
    db.session.commit()

    flash("Screenshot uploaded! Please wait for verification.", "success")
    return redirect(url_for("home_logged"))



@app.route("/tournaments/load/<int:offset>")
def load_tournaments(offset):
    limit = 5  # ek baar me kitne tournaments

    data = Tournament.query.order_by(Tournament.id.desc()).offset(offset).limit(limit).all()

    tournaments = []

    for t in data:
        tournaments.append({
            "id": t.id,
            "name": t.name,
            "desc": t.desc,
            "location": t.location,
            "image": t.image,
            "date": t.date,
            "entry_fee": t.entry_fee,
            "prize_pool": t.prize_pool,
            "current_players": t.current_players,
            "max_players": t.max_players
        })

    return {"tournaments": tournaments}


@app.route("/admin/verify_result/<int:id>", methods=["POST"])
@admin_required
def verify_result(id):
    r = MatchResults.query.get_or_404(id)
    t = Tournament.query.get_or_404(r.tournament_id)

    kills = int(request.form.get("kills"))
    rank = int(request.form.get("rank"))

    points = calculate_points(rank, kills)

    r.kills = kills
    r.rank = rank
    r.points = points
    r.verified = 1

    db.session.commit()

    if t.status != "completed":
        flash("Results can only be verified after the tournament is completed.", "error")
        return redirect(url_for("tournament_detail", id=t.id))


@app.route("/tournament_details_box/<int:id>")
def tournament_details_box(id):
    tournament = Tournament.query.get_or_404(id)
    return render_template("partial_tournament_box.html", t=tournament)
#cancel tournament 
@app.route("/admin/cancel_tournament/<int:id>")
@admin_required
def cancel_tournament(id):
    t = Tournament.query.get_or_404(id)
    t.status = "cancelled"
    db.session.commit()
    
    flash("Tournament has been cancelled!", "warning")
    return redirect(url_for("admin_panel"))

@app.route('/join_form/<int:id>')
def join_form(id):
    t = Tournament.query.get_or_404(id)

    return render_template(
        'join_form.html',
        t=t,
        tournament=t
    )






@app.route("/submit_join", methods=["POST"])
def submit_join():
    user = get_current_user()
    if not user:
        flash("Please login first!", "error")
        return redirect(url_for("login"))

    t_id = int(request.form.get("tournament_id"))
    t = Tournament.query.get_or_404(t_id)

    # ✅ 1. Tournament status check
    if t.status != "upcoming":
        flash("You can only join upcoming tournaments.", "error")
        return redirect(url_for("home_logged"))

    # ✅ 2. Duplicate join check
    if user_already_joined(user.id, t_id):
        flash("You have already joined this tournament.", "info")
        return redirect(url_for("home_logged"))

    # ✅ 3. Lobby full check
    if t.max_players and (t.current_players or 0) >= t.max_players:
        flash("This tournament lobby is already full.", "error")
        return redirect(url_for("home_logged"))

    # ✅ 4. Safe increment
    t.current_players = (t.current_players or 0) + 1

    # ✅ 5. Participation create
    p = Participation(
        user_id=user.id,
        tournament_id=t_id,
        team_name=request.form.get("teamName"),
        captain_name=request.form.get("capName"),
        captain_bgmi_id=request.form.get("capID"),
        p2_name=request.form.get("p2Name"),
        p2_id=request.form.get("p2ID"),
        p3_name=request.form.get("p3Name"),
        p3_id=request.form.get("p3ID"),
        p4_name=request.form.get("p4Name"),
        p4_id=request.form.get("p4ID"),
        phone=request.form.get("phone"),
        email=request.form.get("email"),
        joined_at=str(datetime.now()),
        status="joined"
    )

    db.session.add(p)
    db.session.commit()

    flash("Successfully joined the tournament!", "success")
    return redirect(url_for("home_logged"))


@app.route("/admin/publish_result/<int:id>")
@admin_required
def publish_result(id):
    results = MatchResults.query.filter_by(tournament_id=id).all()
    tournament = Tournament.query.get(id)

    # points ke basis par sort
    sorted_results = sorted(results, key=lambda x: x.points, reverse=True)

    # Top 3 rewards (example)
    prizes = [tournament.prize_pool * 0.5, tournament.prize_pool * 0.3, tournament.prize_pool * 0.2]
    if tournament.result_published:
            flash("Result already published.", "info")
            return redirect(url_for("tournament_detail", id=id))

    if tournament.status != "completed":
        flash("Tournament is not completed yet.", "error")
        return redirect(url_for("tournament_detail", id=id))
    
    for i, r in enumerate(sorted_results):
        if i < len(prizes):
            r.prize = prizes[i]

            # Add to wallet
            wallet = Wallet.query.filter_by(user_id=r.user_id).first()
            wallet.balance += r.prize

        else:
            r.prize = 0
    tournament.result_published = 1
    tournament.result_published = True

    db.session.commit()

    flash("Result published and prize credited!", "success")
    return redirect(url_for("admin_panel"))

@app.route("/tournament_result/<int:id>")
def tournament_result(id):
    t = Tournament.query.get_or_404(id)
    results = MatchResults.query.filter_by(tournament_id=id).order_by(MatchResults.points.desc()).all()

    users = {}
    for r in results:
        users[r.user_id] = User.query.get(r.user_id)

    return render_template("tournament_result.html", t=t, results=results, users=users)



# Ads CRUD
@app.route("/delete_ad/<int:id>", methods=["GET","POST"])
def delete_ad_public(id):
    ad = Ad.query.get_or_404(id)
    db.session.delete(ad)
    db.session.commit()
    flash(f"Ad {ad.title} deleted", "success")
    return redirect(url_for("admin_panel"))

@app.route("/edit_ad/<int:id>", methods=["POST"])
def edit_ad_public(id):
    ad = Ad.query.get_or_404(id)
    ad.title = request.form["title"]
    ad.desc = request.form["desc"]
    db.session.commit()
    flash(f"Ad {ad.title} updated", "success")
    return redirect(url_for("admin_panel"))

@app.route("/add_ad", methods=["POST"])
def add_ad_public():
    title = request.form.get("title")
    desc = request.form.get("desc")
    ad = Ad(title=title, desc=desc)
    db.session.add(ad)
    db.session.commit()
    flash(f"Ad {title} added", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/add_ad", methods=["POST"])
@admin_required
def add_ad_main():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    
    title = request.form.get("title")
    desc = request.form.get("desc")
    image_url = request.form.get("image_url")
    link_url = request.form.get("link_url")

    if not title or not desc or not image_url :
        flash("⚠️ All fields are required!", "error")
        return redirect(url_for("admin_panel"))

    new_ad = Ad(
        title=title,
        desc=desc,
        image_url=image_url,
        link_url=link_url,
        is_active=True
    )
    db.session.add(new_ad)
    db.session.commit()
    flash("✅ Ad added successfully!", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/ads", methods=["GET", "POST"])
@admin_required
def manage_ads():
    if request.method == "POST":
        title = request.form.get("title")
        desc = request.form.get("desc")
        if title and desc:
            try:
                new_ad = Ad(title=title, desc=desc)
                db.session.add(new_ad)
                db.session.commit()
                flash("✅ Ad added successfully!", "success")
            except Exception as e:
                print("❌ Error adding ad:", e)
                db.session.rollback()
                flash("⚠️ Something went wrong while adding ad!", "error")
        else:
            flash("❗ Title and description are required!", "warning")
        return redirect(url_for("manage_ads"))

    try:
        ads = Ad.query.all()
    except Exception as e:
        ads = []
        print("⚠️ Error loading ads:", e)
        flash("⚠️ Could not load ads from database.", "error")

    return render_template("admin_ads.html", ads=ads)

@app.route("/admin/ads-test")
@admin_required
def admin_ads_test():
    return render_template("admin_ads.html", ads=Ad.query.all())

@app.route("/admin/update_ad/<int:ad_id>", methods=["POST"])
@admin_required
def update_ad(ad_id):
    try:
        ad = Ad.query.get_or_404(ad_id)
        ad.title = request.form["title"]
        ad.desc = request.form["desc"]
        db.session.commit()
        flash("✅ Ad updated successfully!", "success")
    except Exception as e:
        print("❌ Error updating ad:", e)
        db.session.rollback()
        flash("⚠️ Something went wrong while updating ad!", "error")
    return redirect(url_for("manage_ads"))

@app.route("/admin/delete_ad/<int:ad_id>")
@admin_required
def delete_ad_admin(ad_id):
    try:
        ad = Ad.query.get_or_404(ad_id)
        db.session.delete(ad)
        db.session.commit()
        flash("🗑️ Ad deleted!", "info")
    except Exception as e:
        print("❌ Error deleting ad:", e)
        db.session.rollback()
        flash("⚠️ Something went wrong while deleting ad!", "error")
    return redirect(url_for("manage_ads"))

# Profile & participation routes
@app.route('/profile')
def profile():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    participations = Participation.query.filter_by(user_id=user.id).all()
    return render_template('home.html', user=user, participations=participations)

@app.route('/complete_tournament/<int:participation_id>', methods=['POST'])
def complete_tournament(participation_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    p = Participation.query.get_or_404(participation_id)
    if p.user_id != user.id and not session.get('admin_logged_in'):
        abort(403)

    p.status = 'completed'
    db.session.commit()
    flash("Tournament marked as completed.", "success")
    return redirect(url_for('home'))
# ---------- Part 4/4 ----------
# app.py - Part 4/4: background updater, forgot/reset password, mail, stats, errors, main

# ------- TOURNAMENT STATUS UPDATER -------
def update_tournament_status():
    """Background updater (fixed)"""
    while True:
        try:
            with app.app_context():
                now = datetime.now()
                tournaments = Tournament.query.all()

                for t in tournaments:
                    if not t.start_time:
                        continue

                    duration = t.duration if t.duration else 30
                    start = t.start_time
                    end = start + timedelta(minutes=duration)

                    if start <= now <= end:
                        if t.status != "ongoing":
                            t.status = "ongoing"
                            db.session.commit()

                    elif now > end:
                        if t.status != "completed":
                            t.status = "completed"
                            db.session.commit()

            time.sleep(60)

        except Exception as e:
            print(f"[ERROR] Tournament Status Updater: {e}")
            time.sleep(60)



# Start background thread (only once)
def start_status_updater():
    updater_thread = Thread(target=update_tournament_status, daemon=True)
    updater_thread.start()

start_status_updater()

# Forgot Password (email via Flask-Mail)
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt="password-reset-salt")
            reset_link = url_for("reset_password", token=token, _external=True)

            msg = Message(
                "Password Reset Request - OFFICIAL ESPORTS",
                recipients=[email]
            )
            msg.body = f'''Hello {user.username},

You requested to reset your password.
Click the link below to reset it (valid for 10 minutes):

{reset_link}

If you didn’t request this, ignore this email.

Best regards,
OFFICIAL ESPORTS Team
'''
            try:
                mail.send(msg)
                flash("✅ Password reset link sent! Check your email inbox.", "success")
            except Exception as e:
                print("Mail error:", e)
                flash("⚠️ Failed to send email. Please check mail settings.", "error")
        else:
            flash("❌ No user found with this email!", "error")
        return redirect(url_for("forgot_password"))
    return render_template("forgot_password.html")

# Reset Password
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = s.loads(token, salt="password-reset-salt", max_age=600)  # 10 min valid
    except Exception:
        flash("The reset link is invalid or expired!", "error")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first_or_404()

    if request.method == "POST":
        new_password = request.form["password"]
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Password updated successfully!", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", email=email)

# Test mail route
@app.route("/test_mail")
def test_mail():
    try:
        msg = Message(
            subject="Flask-Mail Test",
            recipients=["jaydevmahato224@gmail.com"],
            body="✅ Flask-Mail setup successful! This is a test email."
        )
        mail.send(msg)
        return "✅ Test mail sent successfully!"
    except Exception as e:
        import traceback
        print("=== ERROR LOG START ===")
        traceback.print_exc()
        print("=== ERROR LOG END ===")
        return f"❌ Error sending email: {str(e)}"

# User counts & lists
@app.route("/get_user_counts")
def get_user_counts():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    inactive_users = total_users - active_users
    result = {"total": total_users, "active": active_users, "inactive": inactive_users}
    return jsonify(result)

@app.route("/get_users/<status>")
def get_users(status):
    if status == "active":
        users = User.query.filter_by(is_active=True).all()
    elif status == "inactive":
        users = User.query.filter_by(is_active=False).all()
    else:
        users = User.query.all()
    result = []
    for u in users:
        result.append({
            "username": u.username,
            "email": u.email,
            "mobilenumber": u.mobilenumber,
            "is_active": u.is_active
        })
    return jsonify(result)

#tournament joined user pdf generated ----
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

@app.route("/admin/download_players/<int:id>")
@admin_required
def download_players(id):
    tournament = Tournament.query.get_or_404(id)
    participants = Participation.query.filter_by(tournament_id=id).all()

    filename = f"tournament_{id}_players.pdf"
    filepath = os.path.join("static", "pdf", filename)

    os.makedirs(os.path.join("static", "pdf"), exist_ok=True)

    c = canvas.Canvas(filepath, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, f"Tournament Participants - {tournament.name}")

    c.setFont("Helvetica", 12)
    y = 720

    for p in participants:
        user = User.query.get(p.user_id)
        line = f"User ID: {user.id} | Name: {user.username} | Email: {user.email}"
        c.drawString(50, y, line)
        y -= 20
        if y < 50:  # new page
            c.showPage()
            c.setFont("Helvetica", 12)
            y = 750

    c.save()

    return send_from_directory("static/pdf", filename, as_attachment=True)
 


# --------------------------------------------
# DOWNLOAD JOINED PLAYERS PDF (FIXED)
# --------------------------------------------
@app.route("/admin/download_joined/<int:id>")
@admin_required
def download_joined(id):
    participants = Participation.query.filter_by(tournament_id=id).all()

    filename = f"joined_{id}.pdf"
    filepath = os.path.join("static", filename)

    c = canvas.Canvas(filepath)
    c.setFont("Helvetica", 12)

    y = 800
    c.drawString(50, y, f"Tournament ID: {id} — Joined Players")
    y -= 30

    for p in participants:
        text = f"{p.team_name} | Captain: {p.captain_name} ({p.captain_bgmi_id}) | Phone: {p.phone}"
        c.drawString(50, y, text)
        y -= 20
        if y < 50:
            c.showPage()
            c.setFont("Helvetica", 12)
            y = 800

    c.save()
    return send_file(filepath, as_attachment=True)



# ------------------------------------------------
# 🔥 FIXED: RESULT NOTIFICATION BLOCK SAFELY PLACED
# ------------------------------------------------
def notify_tournament_results(t):
    """Notify all participants when tournament completed."""
    if t.status == "completed" and (not getattr(t, "notified", False)):
        participants = Participation.query.filter_by(tournament_id=t.id).all()

        for p in participants:
            try:
                msg = Message(
                    subject="Tournament Result Update",
                    sender="YOUR_EMAIL@gmail.com",
                    recipients=[p.email],
                    body=f"Hello {p.captain_name},\nYour tournament results will be available soon!"
                )
                mail.send(msg)
            except Exception as e:
                print("Mail send error:", e)

        t.notified = True
        db.session.commit()



# --------------------------------------------
# CALCULATE POINTS (FULLY CORRECT)
# --------------------------------------------
def calculate_points(rank, kills):
    
    rank_points_table = {
        1: 15,
        2: 12,
        3: 10,
        4: 8,
        5: 6,
        6: 4,
        7: 2
    }

    if 8 <= rank <= 12:
        rank_points = 1
    else:
        rank_points = rank_points_table.get(rank, 0)

    return rank_points + kills


# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.route("/test500")
def test500():
    raise Exception("Test Internal Server Error")

@app.route('/test')
def test():
    return "Flask working fine!"
# ---------- GLOBAL ERROR HANDLER (SAFE) ----------
@app.errorhandler(Exception)
def handle_all_exceptions(e):
    # Log stack trace
    tb = traceback.format_exc()
    app.logger.error("Unhandled Exception: %s\n%s", str(e), tb)
    # You can add a notification hook here (email/slack) if desired
    # Return friendly page
    try:
        return render_template("500.html", error=str(e)), 500
    except Exception:
        # If template render fails, return plain text
        return "Internal server error", 500

@app.route('/client_error', methods=['POST'])
def client_error():
    data = request.get_json()
    app.logger.error("Client JS Error: %s", data)
    return '', 204

# ---------- HEALTH CHECK ----------
from sqlalchemy import text  # ⬅️ बस यह import add करना है

@app.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return {"status": "ok"}, 200
    except Exception as ex:
        return {"status": "fail", "error": str(ex)}, 500

# ---------- BACKGROUND SELF-HEAL WORKER ----------
# register as scheduler job
def self_heal_tasks():
    try:
        with app.app_context():   # ← magic fix
            ensure_user_wallets()
            reconcile_tournament_counts()
            retry_failed_payments()
    except Exception as e:
        app.logger.error("Self-heal error: %s", str(e))


scheduler.add_job(self_heal_tasks, 'interval', seconds=60, id='self_heal')

def start_self_heal_thread():
    t = threading.Thread(target=self_heal_tasks, args=(), daemon=True)
    t.start()

# call inside main run (see below)

# Initialize DB & run
if __name__ == "__main__":
    try:
        with app.app_context():
            db.create_all()
        # start any background threads or schedulers BEFORE running app
        start_status_updater()     # already called earlier; ensure called only once
        start_self_heal_thread()
        app.logger.info("✅ Database initialized successfully! Starting app...")
        app.run(debug=True)
    except Exception as e:
        import traceback
        app.logger.error("❌ Error while starting Flask app:\n%s", traceback.format_exc())
