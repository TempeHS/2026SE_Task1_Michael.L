from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import jsonify
from flask import url_for
from flask import session
from flask import make_response
from flask.sessions import SecureCookieSessionInterface
from datetime import timedelta
from functools import wraps
import requests
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import logging
import pyopt
import pyqrcode
import os
import base64
from io import BytesIO
import secrets
import userManagement as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")

app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)

# Generate a unique basic 16 key: https://acte.ltd/utils/randomkeygen
app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"
csrf = CSRFProtect(app)


# Redirect index.html to domain root for consistent UX
@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def root():
    return redirect("/", 302)


@app.route("/", methods=["POST", "GET"])
@csp_header(
    {
        # Server Side CSP is consistent with meta CSP in layout.html
        "base-uri": "'self'",
        "default-src": "'self'",
        "style-src": "'self'",
        "script-src": "'self'",
        "img-src": "'self' data:",
        "media-src": "'self'",
        "font-src": "'self'",
        "object-src": "'self'",
        "child-src": "'self'",
        "connect-src": "'self'",
        "worker-src": "'self'",
        "report-uri": "/csp_report",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "frame-src": "'none'",
    }
)
def index():
    return render_template("/index.html")


@app.route("/privacy.html", methods=["GET"])
def privacy():
    return render_template("/privacy.html")


@app.route("/login.html", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        if dbHandler.VerifyUser(email, password):
            session.clear()
            session["user"] = email
            session["SID"] = secrets.token_urlsafe(32)
            session.permanent = False
            response = make_response(redirect("/2fa.html"))
            serializer = SecureCookieSessionInterface().get_signing_serializer(app)
            cookie_value = serializer.dumps(dict(session))
            cookie_name = app.config.get("SESSION_COOKIE_NAME", "session")
            response.set_cookie(
                cookie_name,
                cookie_value,
                httponly=True,
                secure=True,
                samesite="Lax",
            )
            return response
        else:
            return render_template("/login.html", error="Invalid Email or Password")
    else:
        return render_template("/login.html")


@app.route("/logout.html", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect("/index.html")


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        if dbHandler.insertUser(email, password):
            return render_template("/signup.html", is_done=True)
        else:
            return render_template("/signup.html", dupe=True)
    else:
        return render_template("/signup.html")


@app.route("/addlogs.html", methods=["POST", "GET"])
def addlogs():
    if request.method == "POST":
        developer = request.form["developer"]
        project = request.form["project"]
        repo = request.form["repo"]
        start_time = request.form["start_time"]
        end_time = request.form["end_time"]
        log_entry_time = request.form["log_entry_time"]
        time_worked = request.form["time_worked"]
        developer_notes = request.form["developer_notes"]
        if dbHandler.insertLogs(
            developer,
            project,
            repo,
            start_time,
            end_time,
            log_entry_time,
            time_worked,
            developer_notes,
        ):
            return render_template("/addlogs.html", is_done=True)
        else:
            return render_template("/addlogs.html", error=True)
    else:
        return render_template("/addlogs")


@app.route("/2fa.html", methods=["POST", "GET"])
def twofactorauth():
    if "user" not in session:
        return redirect("/login.html")
    return render_template("/2fa.html")


def login_required(f):
    @wraps(f)
    def login_required_decoration(*args, **kwargs):
        if "user" not in session:
            return redirect("/login.html")
        return f(*args, **kwargs)

    return login_required_decoration


@app.route("/datalogs.html", methods=["POST", "GET"])
@login_required
def datalogs():
    if request.method == "POST":
        return render_template("/addlogs.html")
    filter_by_dev = request.args.get("developer", None)
    if filter_by_dev:
        all_devs = dbHandler.get_all_devs()
        if filter_by_dev not in all_devs:
            filter_by_dev = None
    user_logs = dbHandler.getLogs(filter_by_dev)
    developers = dbHandler.get_all_devs()
    return render_template(
        "/datalogs.html", logs=user_logs, developers=developers, filter=filter_by_dev
    )


@app.route("/logdetails/<int:log_id>", methods=["GET"])
@login_required
def logdetails(log_id):
    log = dbHandler.getLogByID(log_id)
    if not log:
        return redirect("/datalogds.html")
    return render_template("/logdetails.html", log=log)


# example CSRF protected form
@app.route("/form.html", methods=["POST", "GET"])
def form():
    if request.method == "POST":
        email = request.form["email"]
        text = request.form["text"]
        return render_template("/form.html")
    else:
        return render_template("/form.html")


# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
