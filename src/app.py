#
#  # This file is part of Hero2Tech Project
#  # Copyright (C) 2024 Muhammad Haroon (Techy-Haroon)
#  #
#  # This program is free software: you can redistribute it and/or modify
#  # it under the terms of the GNU General Public License as published by
#  # the Free Software Foundation, either version 3 of the License, or
#  # (at your option) any later version.
#  #
#  # This program is distributed in the hope that it will be useful,
#  # but WITHOUT ANY WARRANTY; without even the implied warranty of
#  # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  # GNU General Public License for more details.
#  #
#  # You should have received a copy of the GNU General Public License
#  # along with this program. If not, see <https://www.gnu.org/licenses/>.
#  # GitHub Repository: https://github.com/Techy-Haroon/Hero2Tech-Currency-Conversion-API
#

# app.py

from flask import (
    Flask,
    Response,
    g,
    render_template,
    request,
    redirect,
    jsonify,
    url_for,
    session,
    send_from_directory,
    make_response,
    flash,
    abort,
    get_flashed_messages,
)
from email_validator import validate_email, EmailNotValidError
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_dance.contrib.google import make_google_blueprint, google
from flask_caching import Cache
from flask_talisman import Talisman
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from helpers.db.db_init import db
from helpers.email.email_utils import (
    generate_reset_email_content,
    generate_email_confirmation_content,
)
from datetime import datetime, timedelta, timezone, date
import bcrypt
import json
import requests
import string
import os
import secrets
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
import re
import logging
import uuid

app = Flask(__name__)
load_dotenv()
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True, "pool_recycle": 400}
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT"))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS") == "True"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    hours=int(os.getenv("PERMANENT_SESSION_LIFETIME_HOURS"))
)
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE") == "True"
app.config["SESSION_COOKIE_HTTPONLY"] = os.getenv("SESSION_COOKIE_HTTPONLY") == "True"
app.config["REMEMBER_COOKIE_SECURE"] = os.getenv("REMEMBER_COOKIE_SECURE") == "True"
app.config["REMEMBER_COOKIE_HTTPONLY"] = os.getenv("REMEMBER_COOKIE_HTTPONLY") == "True"

app.config["FORCE_HTTPS"] = os.getenv("FORCE_HTTPS") == "True"

app.config["DEBUG"] = os.getenv("DEBUG") == "True"
app.config["TESTING"] = os.getenv("TESTING") == "True"

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
db.init_app(app)
mail = Mail(app)

cache = Cache(config={"CACHE_TYPE": "simple"})
cache.init_app(app)

# Set up logging
logging.basicConfig(level=os.getenv("LOGGING_LEVEL", "INFO"))

google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_to="google_authorized",
    scope=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
    ],
)
app.register_blueprint(google_bp, url_prefix="/login/social")

app.config["HCAPTCHA_SITE_KEY"] = os.getenv("HCAPTCHA_SITE_KEY")
app.config["HCAPTCHA_SECRET_KEY"] = os.getenv("HCAPTCHA_SECRET_KEY")

csp = {
    "default-src": [
        "'self'",
        "https://hcaptcha.com",
        "https://*.hcaptcha.com",
        "https://www.gstatic.com",
    ],
    "script-src": [
        "'self'",
        "'unsafe-inline'",
        "https://hcaptcha.com",
        "https://*.hcaptcha.com",
        "https://www.gstatic.com",
    ],
    "style-src": ["'self'", "https://www.gstatic.com", "https://fonts.googleapis.com"],
    "img-src": "'self' data:",
    "frame-src": ["'self'", "https://hcaptcha.com", "https://*.hcaptcha.com"],
    "base-uri": "'self'",
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=["script-src", "style-src"],
    force_https=app.config["FORCE_HTTPS"],
)

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()

#Initializing Database and Forms Classes
from helpers.db.db_models import User, ApiKey, ApiKeyAction
from helpers.forms.all_forms import SignupForm, CompleteSignupForm, LoginForm, ForgotPasswordForm, EmailConfirmationForm, ResetPasswordForm, UpdateProfileForm, FeatureRequestForm, ReportProblemForm, ContactUsForm

def send_confirmation_email(user):
    confirmation_token = serializer.dumps(user.email, salt="email-confirmation-salt")
    confirmation_token_expiration = datetime.utcnow() + timedelta(minutes=5)
    user.confirmation_token = confirmation_token
    user.confirmation_token_expiration = confirmation_token_expiration
    db.session.commit()

    confirmation_url = url_for(
        "confirm_email", token=confirmation_token, _external=True
    )
    msg = Message(
        "Your Hero2Tech Account Confirmation",
        sender="verify@hero2tech.com",
        recipients=[user.email],
    )
    msg.html = generate_email_confirmation_content(confirmation_url)
    mail.send(msg)
    db.session.close()


def hash_password(password):

    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(hashed_password, plain_password):
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def generate_api_key():
    while True:
        prefix_chars = string.ascii_letters + string.digits
        prefix = secrets.choice(prefix_chars)
        token = secrets.token_urlsafe(32)
        api_key = prefix + token
        existing_key = ApiKey.query.filter_by(api_key=api_key).first()
        if not existing_key:
            return api_key


def get_api_key_user(api_key):
    api_key_record = ApiKey.query.filter_by(api_key=api_key).first()
    return api_key_record.user if api_key_record else None


currency_data = {}
return_currencies = {}
with open("helpers/currencies/currencies.json", "r") as f:
    currency_data = json.load(f)
with open("helpers/currencies/return_currencies.json", "r") as f:
    return_currencies = json.load(f)


def update_currency_data():
    global currency_data
    global return_currencies
    with open("helpers/currencies/currencies.json", "r") as f:
        currency_data = json.load(f)
    with open("helpers/currencies/return_currencies.json", "r") as f:
        return_currencies = json.load(f)


# Schedule the update_currency_data function to run every 10 minutes
scheduler.add_job(func=update_currency_data, trigger="interval", minutes=10)

def convert_currency(from_currency, to_currency, amount):
    from_currency = from_currency.upper()
    to_currency = to_currency.upper()
    if from_currency not in currency_data or to_currency not in currency_data:
        return None

    from_rate = currency_data[from_currency]["value"]
    to_rate = currency_data[to_currency]["value"]
    converted_amount = (amount / from_rate) * to_rate

    data = {
        "converted_amount": converted_amount,
        "given_amount": amount,
        "from_country": currency_data[from_currency]["country"],
        "to_country": currency_data[to_currency]["country"],
        "from_code": from_currency,
        "to_code": to_currency,
    }
    return json.dumps(data, sort_keys=False)


def convert_base_currency(base_currency, target_currencies, amount=1):
    # Check if the base currency exists
    if base_currency not in currency_data:
        return {"error": "Invalid base currency code"}

    # Get the base currency's rate
    from_rate = currency_data[base_currency]["value"]

    # Prepare a dictionary to store conversion results
    conversion_results = {}

    # Loop through target currencies and perform conversion
    for to_currency in target_currencies:
        if to_currency not in currency_data:
            conversion_results[to_currency] = "Invalid currency code"
        else:
            to_rate = currency_data[to_currency]["value"]
            converted_amount = (amount / from_rate) * to_rate
            conversion_results[to_currency] = converted_amount

    return json.dumps(conversion_results, sort_keys=False)


def fetch_usage_data_from_db(user_id):
    user = User.query.filter_by(id=user_id).first()
    total_limit = user.request_limit
    usage_count = user.request_count
    start_timestamp = user.first_request_timestamp
    if start_timestamp != None:
        start_timestamp = str(start_timestamp)
    db.session.close()
    remaining_hits = total_limit - usage_count
    return total_limit, usage_count, remaining_hits, start_timestamp


def get_usage_data(user_id):
    cache_key = f"usage_data_{user_id}"
    cached_data = cache.get(cache_key)

    if cached_data is None:
        # Cache is expired or doesn't exist, fetch from DB
        total_limit, usage_count, remaining_hits, start_timestamp = (
            fetch_usage_data_from_db(user_id)
        )
        cached_data = {
            "total_limit": total_limit,
            "usage_count": usage_count,
            "remaining_hits": remaining_hits,
            "start_timestamp": start_timestamp,
        }
        cache.set(cache_key, cached_data, timeout=5 * 60)

    return cached_data


def get_user_by_id(user_id):
    user = User.query.filter_by(id=user_id).first()
    return user


def get_api_key_by_id(user_id):
    user = ApiKey.query.filter_by(user_id=user_id).first()
    return user.api_key


def get_action_count(user_id, action_type):
    today = date.today()
    count = ApiKeyAction.query.filter_by(
        user_id=user_id, action_type=action_type, action_date=today
    ).first()
    return count.action_count if count else 0


def update_action_count(user_id, action_type):
    today = date.today()
    action = ApiKeyAction.query.filter_by(
        user_id=user_id, action_type=action_type, action_date=today
    ).first()
    if action:
        action.action_count += 1
    else:
        new_action = ApiKeyAction(
            user_id=user_id, action_type=action_type, action_date=today, action_count=1
        )
        db.session.add(new_action)
    db.session.commit()
    db.session.close()


def calculate_reset_date(last_reset_date):
    if last_reset_date == None:
        return None
    last_reset_date = datetime.strptime(last_reset_date, "%Y-%m-%d %H:%M:%S")
    # Increment month by one for the next reset date
    next_month = last_reset_date.month % 12 + 1
    next_year = last_reset_date.year if next_month > 1 else last_reset_date.year + 1
    try:
        next_reset_date = last_reset_date.replace(year=next_year, month=next_month)
    except ValueError:
        # Handles the case for the end of February or other date issues
        if next_month == 2:  # February case, no 29, 30, 31
            next_reset_date = datetime(next_year, next_month, 28)
        else:
            # This block will run if the next month has fewer days (like April, June, September, November)
            next_reset_date = datetime(next_year, next_month, 30)
    return next_reset_date


def time_until_reset(last_reset_date):
    if last_reset_date == None:
        return "You haven't sent any request ever."
    now = datetime.now()
    next_reset_date = calculate_reset_date(last_reset_date)
    if now >= next_reset_date:
        return "You haven't sent any request this month."

    # Time until next reset
    time_difference = next_reset_date - now
    days = time_difference.days
    hours, remainder = divmod(time_difference.seconds, 3600)
    minutes, _ = divmod(remainder, 60)

    if days > 0:
        return f"{days} days until your limit resets."
    elif hours > 0:
        return f"{hours} hours until your limit resets."
    else:
        return f"{minutes} minutes until your limit resets."


def clean_username(username):
    username = username.replace(" ", "_")
    username = re.sub(r"[^\w-]", "", username)
    return username


@app.before_request
def check_cookie():
    darkMode = request.cookies.get("darkMode")
    if darkMode:
        if darkMode == "enabled":
            g.darkMode = True
        elif darkMode == "disabled":
            g.darkMode = False
    else:
        g.darkMode = None


# Step 2: Use a context processor to pass variables to all templates
@app.context_processor
def inject_cookie_value():
    return {"darkMode": g.get("darkMode")}


@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error("Server Error: %s", (e))
    return render_template("500.html"), 500


@app.errorhandler(429)
def too_many_requests(e):
    endpoint = request.endpoint
    key = get_remote_address()
    data = rate_limit_data.get(endpoint, {})
    usage = data.get("usage", {}).get(key, [])

    if usage:
        reset_time = usage[-1] + data.get("block_period", 0)
        reset_time_iso = datetime.fromtimestamp(reset_time, tz=timezone.utc).isoformat()
        return (
            render_template(
                "429.html",
                rate_limits={endpoint: reset_time_iso},
                message="Too Many Requests. Please try again later.",
            ),
            429,
        )
    return (
        render_template(
            "429.html", message="Too Many Requests. Please try again later."
        ),
        429,
    )


@app.errorhandler(404)
def internal_server_error(e):
    return render_template("404.html"), 404


@app.errorhandler(403)
def internal_server_error(e):
    return render_template("403.html"), 403


@cache.cached(timeout=86400)
@app.route("/static/styles.css")
def serve_styles():
    response = make_response(send_from_directory(app.static_folder, "styles.css"))
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@cache.cached(timeout=86400)
@app.route("/favicon.ico")
def serve_favicon():
    response = make_response(send_from_directory(app.static_folder, "favicon.ico"))
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@cache.cached(timeout=86400)
@app.route("/static/favicon.ico")
def serve_static_favicon():
    response = make_response(send_from_directory(app.static_folder, "favicon.ico"))
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@cache.cached(timeout=86400)
@app.route("/static/api-main.css")
def serve_api_css():
    response = make_response(send_from_directory(app.static_folder, "api-main.css"))
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@cache.cached(timeout=86400)
@app.route("/static/plans.css")
def serve_plans_css():
    response = make_response(send_from_directory(app.static_folder, "plans.css"))
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@cache.cached(timeout=86400)
@app.route("/static/docs.css")
def serve_docs_css():
    response = make_response(send_from_directory(app.static_folder, "docs.css"))
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@cache.cached(timeout=86400)
@app.route("/static/script.js")
def serve_js():
    response = make_response(send_from_directory(app.static_folder, "script.js"))
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@cache.cached(timeout=86400)
@app.route("/static/notification.js")
def serve_notification():
    response = make_response(send_from_directory(app.static_folder, "notification.js"))
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@cache.cached(timeout=86400)
@app.route("/static/theme.js")
def serve_theme():
    response = make_response(send_from_directory(app.static_folder, "theme.js"))
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@cache.cached(timeout=84600)
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/docs")
def docs():
    return render_template("docs.html")


@app.route("/docs/convert")
def docs_convert():
    return render_template("convert.html")


@app.route("/docs/convert_currencies")
def docs_convert_currencies():
    return render_template("convert_currencies.html")


@app.route("/docs/get_currency_rates")
def get_currency_rate():
    return render_template("get_currency_rates.html")


@app.route("/docs/response_codes")
def response_codes():
    return render_template("response_codes.html")


@app.route("/docs/patreon")
def patreon():
    return render_template("patreon.html")


@app.route("/plans")
def plans():
    return render_template("plans.html")


@app.route("/request_feature", methods=["GET", "POST"])
def request_feature():
    form = FeatureRequestForm()
    if form.validate_on_submit():
        hcaptcha_response = request.form.get("g-recaptcha-response")
        secret_key = app.config["HCAPTCHA_SECRET_KEY"]
        data = {"secret": secret_key, "response": hcaptcha_response}
        verification_url = "https://hcaptcha.com/siteverify"
        verification_response = requests.post(verification_url, data=data)
        verification_result = verification_response.json()
        if not verification_result.get("success"):
            flash("hCaptcha verification failed. Please try again.", "danger")
            return redirect(url_for("request_feature"))

        name = form.name.data
        email = form.email.data
        message = form.message.data

        formspree_url = "https://formspree.io/f/xldrzqqa"
        data = {
            "name": name,
            "email": email,
            "message": message,
        }
        response = requests.post(formspree_url, data=data)

        if response.status_code == 200 or response.status_code == 201:
            flash("Feature request submitted successfully!", "success")
            return redirect(url_for("request_feature"))
        else:
            soup = BeautifulSoup(response.content, "html.parser")
            error_list = soup.find("ul", class_="validation-error-list")
            if error_list:
                errors = [li.text for li in error_list.find_all("li")]
                flash(errors)
            else:
                flash(
                    "An error occurred while submitting your request. Please try again.",
                    "danger",
                )
                return redirect(url_for("request_feature"))
    elif request.method == "POST":
        flash("Form validation failed. Please check your inputs.", "danger")
        return redirect(url_for("request_feature"))

    return render_template(
        "request_feature.html",
        form=form,
        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
    )


@app.route("/report_problem", methods=["GET", "POST"])
def report_problem():
    form = ReportProblemForm()
    if form.validate_on_submit():
        hcaptcha_response = request.form.get("g-recaptcha-response")
        secret_key = app.config["HCAPTCHA_SECRET_KEY"]
        data = {"secret": secret_key, "response": hcaptcha_response}
        verification_url = "https://hcaptcha.com/siteverify"
        verification_response = requests.post(verification_url, data=data)
        verification_result = verification_response.json()
        if not verification_result.get("success"):
            flash("hCaptcha verification failed. Please try again.", "danger")
            return redirect(url_for("report_problem"))

        name = form.name.data
        email = form.email.data
        message = form.message.data

        formspree_url = "https://formspree.io/f/xzzponnw"
        data = {
            "name": name,
            "email": email,
            "message": message,
        }
        response = requests.post(formspree_url, data=data)

        if response.status_code == 200 or response.status_code == 201:
            flash("Report submitted successfully!", "success")
            return redirect(url_for("report_problem"))
        else:
            soup = BeautifulSoup(response.content, "html.parser")
            error_list = soup.find("ul", class_="validation-error-list")
            if error_list:
                errors = [li.text for li in error_list.find_all("li")]
                flash(errors)
            else:
                flash(
                    "An error occurred while submitting your request. Please try again.",
                    "danger",
                )
                return redirect(url_for("report_problem"))
    elif request.method == "POST":
        flash("Form validation failed. Please check your inputs.", "danger")
        return redirect(url_for("report_problem"))

    return render_template(
        "report_problem.html",
        form=form,
        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
    )


@app.route("/contact", methods=["GET", "POST"])
def contact_us():
    form = ContactUsForm()
    if form.validate_on_submit():
        hcaptcha_response = request.form.get("g-recaptcha-response")
        secret_key = app.config["HCAPTCHA_SECRET_KEY"]
        data = {"secret": secret_key, "response": hcaptcha_response}
        verification_url = "https://hcaptcha.com/siteverify"
        verification_response = requests.post(verification_url, data=data)
        verification_result = verification_response.json()
        if not verification_result.get("success"):
            flash("hCaptcha verification failed. Please try again.", "danger")
            return redirect(url_for("contact_us"))

        name = form.name.data
        email = form.email.data
        message = form.message.data

        formspree_url = "https://formspree.io/f/mzzponjl"
        data = {
            "name": name,
            "email": email,
            "message": message,
        }
        response = requests.post(formspree_url, data=data)

        if response.status_code == 200 or response.status_code == 201:
            flash("Message sent successfully!", "success")
            return redirect(url_for("contact_us"))
        else:
            soup = BeautifulSoup(response.content, "html.parser")
            error_list = soup.find("ul", class_="validation-error-list")
            if error_list:
                errors = [li.text for li in error_list.find_all("li")]
                flash(errors)
            else:
                flash(
                    "An error occurred while submitting your request. Please try again.",
                    "danger",
                )
                return redirect(url_for("contact_us"))
    elif request.method == "POST":
        flash("Form validation failed. Please check your inputs.", "danger")
        return redirect(url_for("contact_us"))

    return render_template(
        "contact.html", form=form, hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"]
    )


@app.route("/signup", methods=["GET", "POST"])
# I used this for rate limiting but this is very poor method. You should use another method or just don't use it.
# Platforms like Cloudflare allow you to set these rules on their service. So, just set rules there.
# @custom_rate_limit(limit=3, period=3600, block_period=3600)
def signup():
    if "user_id" in session:
        flash("You are already logged in.", "info")
        return redirect(url_for("dashboard"))
    if "in_process" in session:
        flash("Please complete your signup.", "info")
        return redirect(url_for("complete_signup"))
    form = SignupForm()
    if form.validate_on_submit():
        try:
            if form.password.data == form.confirm_password.data:
                hashed_password = hash_password(form.password.data)
                user_ip = request.remote_addr
                new_user = User(
                    username=form.username.data,
                    email=form.email.data,
                    password=hashed_password,
                    first_name=True,
                    ip_signup=user_ip,
                )
                send_confirmation_email(new_user)
                db.session.add(new_user)

                db.session.commit()
                db.session.close()
                flash(
                    "A confirmation email has been sent. Please check your email.",
                    "info",
                )
                return redirect(url_for("login"))
            else:
                flash("Both Passwords doesn't match. Try again", "danger")
                return render_template("signup.html", form=form)
        except Exception as e:
            e = str(e)
            username = form.username.data
            email = form.email.data
            if f"Duplicate entry '{username}' for key 'username'" in e:
                db.session.close()
                flash(
                    f"Username {username} is already taken. Please enter another username.",
                    "warning",
                )
            elif f"Duplicate entry '{email}' for key 'email'" in e:
                db.session.close()
                flash(
                    f"Email {email} already exists. Please enter another email.",
                    "warning",
                )
            elif "The mail server could not deliver mail" in e:
                db.session.close()
                flash(
                    f"The email address {email} is not valid. Please enter a valid email address."
                )
            else:
                db.session.close()
                flash("An error occurred. Please try again.")
    else:
        if request.method == "POST":
            flash("Form validation failed. Please check your inputs.", "danger")
            return redirect(url_for("signup"))
    return render_template("signup.html", form=form)


@app.route("/confirm_email/<token>", methods=["GET", "POST"])
def confirm_email(token):
    if "user_id" in session:
        flash("You are already logged in.", "info")
        return redirect(url_for("dashboard"))
    form = EmailConfirmationForm()
    try:
        email = serializer.loads(token, salt="email-confirmation-salt", max_age=300)
    except:
        try:
            email = serializer.loads(token, salt="email-confirmation-salt")
            flash(
                f"""
            <p>The confirmation link has expired. Request a new one?</p>
            <form action="{url_for('resend_confirmation')}" method="POST" class="re-div">
                {form.hidden_tag()}
                <input type="hidden" name="email" value="{email}">
                <button type="submit" class="hero-btn">Resend Confirmation</button>
            </form>
            """,
                "warning",
            )
        except:
            flash("Confirmation link is invalid.", "error")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first_or_404()
    if user:
        if user.confirmation_token != token:
            db.session.close()
            flash("Confirmation link is invalid.", "error")
            return redirect(url_for("login"))
        elif datetime.utcnow() > user.confirmation_token_expiration:
            db.session.close()
            flash(
                f"""
                <p>The confirmation link has expired. Request a new one?</p>
                <form action="{url_for('resend_confirmation')}" method="POST" class="re-div">
                    {form.hidden_tag()}
                    <input type="hidden" name="email" value="{email}">
                    <button type="submit" class="hero-btn">Resend Confirmation</button>
                </form>
                """,
                "warning",
            )
            return redirect(url_for("login"))

        if user.confirmed:
            db.session.close()
            flash("Account already confirmed. Please log in.", "info")
        else:
            user.confirmed = True
            user.confirmation_token = None
            user.confirmation_token_expiration = None
            db.session.commit()

            # Generate and save API key
            new_api_key = ApiKey(user_id=user.id, api_key=generate_api_key())
            db.session.add(new_api_key)
            db.session.commit()

            db.session.close()
            flash("Email confirmed. You can now log in.", "info")

        return redirect(url_for("login"))
    else:
        flash("Confirmation link is invalid.", "error")
        return redirect(url_for("login"))


@app.route("/resend_confirmation", methods=["POST"])
def resend_confirmation():
    if "user_id" in session:
        flash("You are already logged in.", "info")
        return redirect(url_for("dashboard"))
    form = EmailConfirmationForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        if email:
            user = User.query.filter_by(email=email).first()
            if user:
                if user.confirmed:
                    db.session.close()
                    flash("Account already confirmed. Please log in.", "info")
                else:
                    send_confirmation_email(user)
                    db.session.close()
                    flash(
                        "A new confirmation email has been sent. Please check your email.",
                        "info",
                    )
            else:
                db.session.close()
                flash("Email not found. Please sign up.")
        else:
            flash("No email provided.", "danger")
        return redirect(url_for("login"))
    else:
        flash("Invalid Request.", "warning")
        return redirect(url_for("login"))


@app.route("/signup/complete", methods=["GET", "POST"])
def complete_signup():
    if "user_id" in session:
        flash("You are already logged in.", "info")
        return redirect(url_for("dashboard"))
    if "in_process" not in session:
        flash("Invalid Request.", "danger")
        return redirect(url_for("login"))
    if "in_process" in session:
        complete_time = session.get("complete_time")
        if complete_time:
            time_elapsed = datetime.utcnow().replace(tzinfo=pytz.utc) - complete_time
            if time_elapsed > timedelta(minutes=5):
                del session["in_process"]
                del session["complete_time"]
                flash(
                    "Your Signup session got expired. Please signup again.", "warning"
                )
                return redirect(url_for("signup"))
        else:
            del session["in_process"]
            flash("An Unexpected error occured. Please signup again.", "warning")
            return redirect(url_for("signup"))
    form = CompleteSignupForm()
    email = session.get("email")
    if not email:
        flash("Invalid Request.", "danger")
        return redirect(url_for("login"))
    if form.validate_on_submit():
        # Perform validation
        if (
            not form.username.data
            or not form.password.data
            or not form.confirm_password.data
        ):
            flash("Username and password are required.", "danger")
            return render_template("complete_signup.html", email=email)
        if form.password.data != form.confirm_password.data:
            flash("Both Passwords doesn't match", "warning")
            return render_template("complete_signup.html", form=form, email=email)
        try:
            # Create the user
            hashed_password = hash_password(form.password.data)
            user_ip = request.remote_addr
            user = User(
                username=form.username.data,
                email=email,
                password=hashed_password,
                social_signup=True,
                confirmed=True,
                first_name=True,
                ip_signup=user_ip,
            )
            db.session.add(user)
            db.session.commit()

            # Generate and save API key
            api_key_for = generate_api_key()
            new_api_key = ApiKey(user_id=user.id, api_key=api_key_for)
            db.session.add(new_api_key)
            db.session.commit()
        except Exception as e:
            app.logger.error(e)
            e = str(e)
            if f"Duplicate entry '{form.username.data}' for key 'username'" in e:
                db.session.close()
                flash(
                    f"Username {form.username.data} is already taken. Please enter another username.",
                    "warning",
                )
            elif f"Duplicate entry '{session.get('email')}' for key 'email'" in e:
                db.session.close()
                flash(
                    f"Email {session.get('email')} has just been signed up. Maybe you signed up on another tab? Try logging out and logging in again.",
                    "warning",
                )
            else:
                db.session.close()
                flash(f"An error occurred. Please try again.")
            return render_template("complete_signup.html", form=form, email=email)

        # Log the user in
        user_ip = request.remote_addr
        if user.ip_last == user_ip:
            pass
        else:
            try:
                user.ip_last = user_ip
                db.session.commit()
            except:
                pass
        session["user_id"] = user.id
        session["email"] = user.email
        session["username"] = user.username
        session["created_at"] = (str(user.created_at))[:-9]  # (UTC+2:00)
        session["api_key"] = get_api_key_by_id(user.id)
        flash(f"Account created and logged in as {user.username}.", "success")
        db.session.close()
        if "in_process" in session:
            del session["in_process"]
            if "complete_time" in session:
                del session["complete_time"]
        return redirect(url_for("dashboard"))
    else:
        if request.method == "POST":
            flash("Form validation failed. Please check your inputs.", "danger")

    # if request.method == 'POST':
    return render_template("complete_signup.html", form=form, email=email)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        flash("You are already logged in.")
        return redirect(url_for("dashboard"))
    if "in_process" in session:
        flash("Please complete your signup.", "info")
        return redirect(url_for("complete_signup"))
    form = LoginForm()
    cache.delete_memoized(dashboard)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password(user.password, form.password.data):
                if user.confirmed:
                    user_ip = request.remote_addr
                    if user.ip_last == user_ip:
                        pass
                    else:
                        try:
                            user.ip_last = user_ip
                            db.session.commit()
                        except:
                            pass
                    session["user_id"] = user.id
                    session["username"] = user.username
                    session["email"] = user.email
                    session["created_at"] = (str(user.created_at))[:-9]  # (UTC+2:00)
                    session["api_key"] = get_api_key_by_id(user.id)

                    if form.remember_me.data:
                        session.permanent = True
                        app.permanent_session_lifetime = timedelta(hours=24)
                    else:
                        session.permanent = False
                    db.session.close()
                    flash("Login successful.", "success")
                    return redirect(url_for("dashboard"))
                else:
                    db.session.close()
                    flash(
                        f'<p>Please confirm your email before logging in.<br>Didn\'t receive email or got expired?</p><div style="display: inline-grid; justify-content: center; align-items: center;"><a href="/resend_confirmation/{user.email}" class="hero-btn" style="padding: 15px 20px;">Resend Confirmation</a></div>',
                        "warning",
                    )
            else:
                db.session.close()
                # increment_usage(endpoint="login", limit=5, period=300, block_period=900)
                flash("Invalid email or password.", "danger")
        else:
            db.session.close()
            # increment_usage(endpoint="login", limit=5, period=300, block_period=900)
            flash("Invalid email or password.", "danger")
    else:
        if request.method == "POST":
            flash("Form validation failed. Please check your inputs.", "danger")
    return render_template("login.html", form=form)


@app.route("/login/google")
def login_google():
    if "user_id" in session:
        flash("You are already logged in.")
        return redirect(url_for("dashboard"))
    if not google.authorized:
        return redirect(url_for("google.login"))
    if google.authorized and "user_id" not in session:
        session.clear()
        return redirect(url_for("google.login"))
    flash("You are already logged in.", "message")
    return redirect(url_for("dashboard"))


@app.route("/login/google/authorized")
def google_authorized():
    if "user_id" in session:
        flash("You are already logged in.")
        return redirect(url_for("dashboard"))

    if not google.authorized:
        flash("Authorization failed.", "error")
        return redirect(url_for("login"))

    # Fetch user info from Google
    resp = google.get("/oauth2/v2/userinfo")
    assert resp.ok, resp.text
    user_info = resp.json()

    email = user_info["email"]
    username = user_info["name"]
    username = clean_username(username)
    # You can also access other information like user_info['id'], user_info['picture'], etc.

    # Check if user already exists
    user = User.query.filter_by(email=email).first()
    if not user:
        try:
            session["email"] = email
            session["username"] = username
            session["in_process"] = True
            session["complete_time"] = datetime.utcnow().replace(tzinfo=pytz.utc)
            flash(
                "Signup successful. Please enter your info to complete signup.", "info"
            )
            return redirect(url_for("complete_signup"))

        except Exception as e:
            db.session.close()
            session.clear()
            flash("An error occurred. Please try again.")
            return redirect(url_for("signup"))

    else:
        if not user.confirmed:
            user.confirmed = True
            db.session.commit()
        cache.delete_memoized(dashboard)
        # Log the user in (set session variables)
        user_ip = request.remote_addr
        if user.ip_last == user_ip:
            pass
        else:
            try:
                user.ip_last = user_ip
                db.session.commit()
            except:
                pass
        session["user_id"] = user.id
        session["email"] = user.email
        session["username"] = user.username
        session["created_at"] = (str(user.created_at))[:-9]  # (UTC+2:00)
        session["ask_time"] = datetime.utcnow().replace(tzinfo=pytz.utc)
        session["api_key"] = get_api_key_by_id(user.id)
        db.session.close()
        flash(f"Logged in as {user.username}", "success")
    return redirect(url_for("stay_logged_in"))


@app.route("/stay_logged_in", methods=["GET", "POST"])
def stay_logged_in():
    if "user_id" not in session:
        flash("Invalid Request.", "warning")
        return redirect(url_for("login"))
    if not google.authorized:
        flash("Invalid Request.", "warning")
        return redirect(url_for("login"))
    if "once" in session:
        flash("Invalid Request.", "warning")
        return redirect(url_for("login"))
    ask_time = session.get("ask_time")
    if ask_time:
        time_elapsed_ask = datetime.utcnow().replace(tzinfo=pytz.utc) - ask_time
        if time_elapsed_ask > timedelta(minutes=5):
            session["once"] = True
            del session["ask_time"]
            flash("Invalid Request.", "warning")
            return redirect(url_for("login"))
    else:
        if session.get("ask_time", False) != False:
            del session["ask_time"]
            session["once"] = True
    if request.method == "POST":
        if "stay_logged_in" in request.form:
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=24)
            session["once"] = True
        else:
            session["once"] = True
        return redirect(url_for("dashboard"))
    return render_template("ask_stay_logged_in.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if "user_id" in session:
        flash("You need to be logged out in order to reset password.", "warning")
        return redirect(url_for("dashboard"))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            if user.confirmed != True:
                db.session.close()
                flash(
                    f'<p>Verify account first to Reset Passord.<br>Didn\'t receive verification email or got expired?</p><div style="display: inline-grid; justify-content: center; align-items: center;"><a href="/resend_confirmation/{email}" class="hero-btn" style="padding: 15px 20px;">Resend Confirmation</a></div>',
                    "warning",
                )
                return redirect(url_for("login"))
            # Generate a unique reset token
            reset_token = serializer.dumps(email, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=reset_token, _external=True)

            # Set token expiration time to 5 minutes from now
            user.reset_token = reset_token
            user.reset_token_expiration = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()

            # Send the reset email
            msg = Message(
                "Reset Your Password on Hero2Tech",
                sender="verify@hero2tech.com",
                recipients=[email],
            )
            msg.html = generate_reset_email_content(reset_url)
            mail.send(msg)
            db.session.close()
            flash("A password reset link has been sent to your email address.", "info")
        else:
            db.session.close()
            flash("No account found with that email address.", "warning")

        return redirect(url_for("login"))
    else:
        if request.method == "POST":
            flash("Form validation failed. Please check your inputs.", "danger")

    return render_template("forgot_password.html", form=form)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if "user_id" in session:
        flash("You must be logged out in order to reset password.", "warning")
        return redirect(url_for("dashboard"))
    try:
        email = serializer.loads(
            token, salt="password-reset-salt", max_age=300
        )  # Token valid for 5 minutes
    except:
        flash("The password reset link is invalid or has expired.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()

    # Check if the token is valid and not expired
    if user.reset_token != token or datetime.utcnow() > user.reset_token_expiration:
        db.session.close()
        flash("The password reset link is invalid or has expired.", "danger")
        return redirect(url_for("forgot_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            db.session.close()
            flash("Both Passwords don't match.", "danger")
            return render_template("reset_password.html", form=form)

        previous_password = user.password
        user.password = hash_password(form.password.data)
        if check_password(previous_password, form.password.data):
            db.session.close()
            flash("You can't set same password", "error")
            return render_template("reset_password.html", form=form)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        db.session.close()
        flash(
            "Your password has been updated. You can now log in with your new password.",
            " info",
        )
        return redirect(url_for("login"))

    return render_template("reset_password.html", form=form)


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please login to access dashboard.", "warning")
        return redirect(url_for("login"))
    user_id = session["user_id"]
    usage_data = get_usage_data(user_id)
    user_start_timestamp = time_until_reset(usage_data["start_timestamp"])
    if "days until your limit resets" not in user_start_timestamp:
        usage_data = {"total_limit": 1000, "usage_count": 0, "remaining_hits": 1000}

    get_flashed_messages()
    return render_template(
        "dashboard.html",
        total_limit=usage_data["total_limit"],
        usage_count=usage_data["usage_count"],
        remaining_hits=usage_data["remaining_hits"],
        start_timestamp=user_start_timestamp,
    )


@app.route("/dashboard/api-keys")
def api_keys():
    if "user_id" not in session:
        flash("Please login to access API keys.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    generate_count = get_action_count(user.id, "generate")

    return render_template("api_keys.html", user=user, generate_count=generate_count)


@app.route("/dashboard/generate-api-key", methods=["POST"])
def generate_api_key_route():
    if "user_id" not in session:
        flash("Please login to generate an API key.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    generate_count = get_action_count(user.id, "generate")

    if len(user.api_keys) >= user.max_api_key:
        flash(f"You can have a maximum of {user.max_api_key} API keys.", "warning")
    elif generate_count >= 15:
        flash("You can generate a maximum of 15 API keys per day.", "warning")
    else:
        new_key = generate_api_key()
        api_key = ApiKey(user_id=user.id, api_key=new_key)
        db.session.add(api_key)
        db.session.commit()
        update_action_count(user.id, "generate")
        flash("New API key generated successfully.", "success")

    return redirect(url_for("api_keys"))


@app.route("/dashboard/delete-api-key/<int:key_id>", methods=["POST"])
def delete_api_key(key_id):
    if "user_id" not in session:
        flash("Please login to delete an API key.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if len(user.api_keys) <= 1:
        flash(
            "You already only have 1 API key left. You cannot delete that.", "warning"
        )
        return redirect(url_for("api_keys"))
    else:
        api_key = ApiKey.query.filter_by(id=key_id, user_id=user.id).first()
        if api_key:
            db.session.delete(api_key)
            db.session.commit()
            flash("API key deleted successfully.", "success")
            session["allow"] = True
        else:
            flash("API key not found.", "error")
    return redirect(url_for("update_api_key1"))


@app.route("/end/v1/u")
def update_api_key():
    if "user_id" not in session:
        flash("Invalid Request.", "warning")
        return redirect(url_for("dashboard"))
    user = User.query.get(session["user_id"])
    session["api_key"] = get_api_key_by_id(session["user_id"])
    flash("Your preferences got updated.")
    return redirect(url_for("dashboard"))


@app.route("/end/v2/u")
def update_api_key1():
    if "user_id" not in session:
        flash("Invalid Request.", "warning")
        return redirect(url_for("dashboard"))
    if "allow" in session:
        user = User.query.get(session["user_id"])
        session["api_key"] = get_api_key_by_id(session["user_id"])
        session.pop("allow", None)
        return redirect(url_for("api_keys"))
    else:
        flash("Invalid Request.", "warning")
        return redirect(url_for("dashboard"))


@app.route("/dashboard/update-profile", methods=["GET", "POST"])
def update_profile():
    form = UpdateProfileForm()
    if "user_id" in session:
        current_time = datetime.now()
        user = User.query.filter_by(email=session["email"]).first()
        if user.first_name == False:
            time_elapsed = current_time - user.name_changed_at
            elapsed_seconds = time_elapsed.total_seconds()
            if elapsed_seconds >= 86400:
                pass
            else:
                db.session.close()
                flash(
                    "You cannot change your username more than once in 24 Hours.",
                    "warning",
                )
                return redirect(url_for("dashboard"))
        if form.validate_on_submit():
            new_name = form.username.data
            if not new_name:
                flash("Name is required.", "warning")
                return redirect(url_for("update_profile"))
            if new_name == session["username"]:
                db.session.close()
                flash("Same name cannot be added again.", "warning")
                return redirect(url_for("update_profile"))
            try:
                # Update the user's name in the database
                if user.first_name == True:
                    user.first_name = False
                user.name_changed_at = datetime.now()
                user.username = new_name
                db.session.commit()
                session["username"] = new_name
                flash("Profile updated successfully.", "info")
                db.session.close()
                return redirect(url_for("dashboard"))
            except Exception as e:
                e = str(e)
                db.session.rollback()
                username = new_name
                if f"Duplicate entry '{username}' for key 'username'" in e:
                    db.session.close()
                    flash(
                        f"Username {username} is already taken. Please enter another username.",
                        "warning",
                    )
                else:
                    db.session.close()
                    flash("An error occurred while updating the profile.", "danger")
        else:
            if request.method == "POST":
                flash("Form validation failed. Please check your inputs.", "danger")

        return render_template(
            "update-profile.html", user=session["username"], form=form
        )
    else:
        flash("You must be logged in to update profile.", "warning")
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    if "user_id" in session or "in_process" in session:
        session.clear()
        cache.delete_memoized(dashboard)
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))
    else:
        flash("You are already logged out.", "info")
        return redirect(url_for("login"))


@app.route("/convert", methods=["GET", "POST"])
def convert():
    # Check if Authorization header is present
    auth_header = request.headers.get("Authorization")

    if auth_header:
        try:
            # Extract API key from Authorization header
            api_key = auth_header.split(" ")[1]
        except IndexError:
            res = {"error": "invalid api key"}
            return jsonify(res), 401

        # Extract parameters from JSON body
        data = request.get_json() or {}
        from_currency = data.get("from_currency")
        to_currency = data.get("to_currency")
        amount = data.get("amount")

        # Validate required parameters from JSON body
        if not from_currency or not to_currency or amount is None:
            res = {"error": "missing required parameters in JSON body"}
            return jsonify(res), 400

    else:
        # Authorization header not present, fallback to URL parameters
        api_key = request.args.get("api_key")
        from_currency = request.args.get("from_currency")
        to_currency = request.args.get("to_currency")
        amount = request.args.get("amount", type=float)

        # Validate required parameters from URL
        if not api_key:
            res = {"error": "invalid api key"}
            return jsonify(res), 401
        if not from_currency or not to_currency or amount is None:
            res = {"error": "missing required parameters in URL"}
            return jsonify(res), 400

    # Fetch user associated with the API key
    user = get_api_key_user(api_key)
    if not user:
        res = {"error": "invalid api key"}
        return jsonify(res), 401
    # Handle the user's first request timestamp
    if user.first_request_timestamp is None:
        user.first_request_timestamp = datetime.utcnow()
        db.session.commit()

    now = datetime.utcnow()
    days_since_first_request = (now - user.first_request_timestamp).days

    if days_since_first_request >= 30:
        user.request_count = 0
        user.first_request_timestamp = now
        db.session.commit()

    if user.request_count >= user.request_limit:
        res = {"error": "request limit reached"}
        return jsonify(res), 403

    # Perform currency conversion
    conversion_result = convert_currency(from_currency, to_currency, amount)

    if conversion_result is None:
        res = {"error": "invalid currency code"}
        return jsonify(res), 400

    # Increment the user's request count
    user.request_count += 1
    db.session.commit()
    db.session.close()

    # Return the conversion result as JSON
    return Response(conversion_result, content_type="application/json")


@app.route("/get_currency_rates", methods=["GET"])
def get_currency_rates():
    auth_header = request.headers.get("Authorization")

    if auth_header:
        try:
            # Extract API key from Authorization header
            api_key = auth_header.split(" ")[1]
        except IndexError:
            res = {"error": "invalid api key"}
            return jsonify(res), 401
    else:
        # Authorization header not present, fallback to URL parameters
        api_key = request.args.get("api_key")
        if not api_key:
            res = {"error": "invalid api key"}
            return jsonify(res), 401
    # Fetch user associated with the API key
    user = get_api_key_user(api_key)
    if not user:
        res = {"error": "invalid api key"}
        return jsonify(res), 401
    # Handle the user's first request timestamp
    if user.first_request_timestamp is None:
        user.first_request_timestamp = datetime.utcnow()
        db.session.commit()

    now = datetime.utcnow()
    days_since_first_request = (now - user.first_request_timestamp).days

    if days_since_first_request >= 30:
        user.request_count = 0
        user.first_request_timestamp = now
        db.session.commit()

    if user.request_count >= user.request_limit:
        res = {"error": "request limit reached"}
        return jsonify(res), 403

    # Increment the user's request count
    user.request_count += 1
    db.session.commit()
    db.session.close()

    return jsonify(return_currencies)


@app.route("/convert_currencies", methods=["GET", "POST"])
def convert_currencies_end():
    # Check if Authorization header is present
    auth_header = request.headers.get("Authorization")

    if auth_header:
        try:
            # Extract API key from Authorization header
            api_key = auth_header.split(" ")[1]
        except IndexError:
            res = {"error": "invalid api key"}
            return jsonify(res), 401

        # Extract parameters from JSON body
        data = request.get_json() or {}
        base_currency = data.get("base_currency")
        convert_currencies_str = data.get("convert_currencies")
        amount = data.get("amount")

        # Validate required parameters from JSON body
        if not base_currency or not convert_currencies_str or amount is None:
            res = {"error": "missing required parameters in JSON body"}
            return jsonify(res), 400

    else:
        # Authorization header not present, fallback to URL parameters
        api_key = request.args.get("api_key")
        base_currency = request.args.get("base_currency")
        convert_currencies_str = request.args.get("convert_currencies")
        amount = request.args.get("amount", type=float)

        # Validate required parameters from URL
        if not api_key:
            res = {"error": "invalid api key"}
            return jsonify(res), 401
        if not base_currency or not convert_currencies_str:
            res = {"error": "missing required parameters in URL"}
            return jsonify(res), 400

    # Fetch user associated with the API key
    user = get_api_key_user(api_key)
    if not user:
        res = {"error": "invalid api key"}
        return jsonify(res), 401

    # Handle the user's first request timestamp
    if user.first_request_timestamp is None:
        user.first_request_timestamp = datetime.utcnow()
        db.session.commit()

    now = datetime.utcnow()
    days_since_first_request = (now - user.first_request_timestamp).days

    if days_since_first_request >= 30:
        user.request_count = 0
        user.first_request_timestamp = now
        db.session.commit()

    if user.request_count >= user.request_limit:
        res = {"error": "request limit reached"}
        return jsonify(res), 403

    # Convert convert_currencies_str from a comma-separated string to a list
    target_currencies = [
        currency.strip().upper() for currency in convert_currencies_str.split(",")
    ]
    if not amount:
        amount = 1
    # Perform currency conversions
    conversion_results = convert_base_currency(base_currency, target_currencies, amount)

    # Check for invalid currency codes
    if isinstance(conversion_results, dict) and "error" in conversion_results:
        return jsonify(conversion_results), 400

    # Increment the user's request count
    user.request_count += 1
    db.session.commit()
    db.session.close()

    return Response(conversion_results, content_type="application/json")


@app.route("/currency-api")
def currency_api():
    return render_template("currency_api.html")


if __name__ == "__main__":
    app.run(debug=False)
