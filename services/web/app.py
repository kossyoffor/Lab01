"""Web UI microservice - three pages (Onboard, Offboard, Dashboard). It holds NO IAM
permissions: it can only read its own login secret and call the other services."""
import hmac, os, secrets, time
import requests
from flask import Flask, flash, redirect, render_template, request, session, url_for, abort
from common import nimbus
from common.config import PERSONAS

app = Flask(__name__)
URLS = {"onboarding": os.environ.get("ONBOARD_URL", "http://onboarding:5001"),
        "offboarding": os.environ.get("OFFBOARD_URL", "http://offboarding:5002"),
        "dashboard": os.environ.get("DASHBOARD_URL", "http://dashboard:5003")}
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",   # set on the server, where TLS is on
                  PERMANENT_SESSION_LIFETIME=1800)
MAX_FAILS, LOCK_SECONDS = 5, 300
_fails = {}                                    # remote address -> (count, first failure time); per worker process


@app.after_request
def security_headers(resp):
    """Browser-side defences (a small 'edge' layer, deck Module 5 and 6)."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"                      # pages can contain one-time passwords
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=86400"
    return resp


def _login():
    return nimbus.get_secret("nimbus/web-login")


def _load_key(tries=10):
    for i in range(tries):                      # roles/secrets may still be propagating at boot
        try:
            return _login()["flask_secret_key"]  # session-signing key lives in Secrets Manager
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(3)


app.secret_key = _load_key()


@app.before_request
def guard():
    if request.endpoint in ("login", "static", "healthz"):
        return
    if not session.get("user"):
        return redirect(url_for("login"))
    if request.method == "POST":
        if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            abort(400, "bad CSRF token")
@app.context_processor
def inject():
    session.setdefault("csrf", secrets.token_urlsafe(16))
    return {"csrf": session["csrf"], "user": session.get("user"), "personas": PERSONAS}


def call(svc, method, path, **kw):
    try:
        r = requests.request(method, URLS[svc] + path, timeout=20,
                             headers={"X-Internal-Token": nimbus.internal_token()}, **kw)
        return r.status_code, r.json()
    except (requests.RequestException, ValueError) as e:
        return 503, {"error": f"{svc} service unavailable: {e.__class__.__name__}"}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "web"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "?"
        n, first = _fails.get(ip, (0, 0))
        if n >= MAX_FAILS and time.time() - first < LOCK_SECONDS:
            nimbus.log_event("login_locked_out", remote=ip)
            flash("Too many failed attempts. Try again in a few minutes.", "bad")
            return render_template("login.html"), 429
        cfg = _login()
        ok = (hmac.compare_digest(request.form.get("username", ""), cfg["admin_username"]) &
              hmac.compare_digest(request.form.get("password", ""), cfg["admin_password"]))
        if ok:
            _fails.pop(ip, None)
            nimbus.log_event("login_success", remote=ip)
            session.clear(); session.permanent = True; session["user"] = cfg["admin_username"]
            return redirect(url_for("dashboard"))
        _fails[ip] = (n + 1, first if n and time.time() - first < LOCK_SECONDS else time.time())
        nimbus.log_event("login_failed", remote=ip, attempt=_fails[ip][0])
        flash("Invalid credentials", "bad")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/onboard", methods=["GET", "POST"])
def onboard():
    result = None
    if request.method == "POST":
        f = request.form
        code, body = call("onboarding", "POST", "/onboard", json={
            "username": f.get("username"), "full_name": f.get("full_name"), "email": f.get("email"),
            "persona": f.get("persona"), "console_access": f.get("console_access") == "on",
            "actor": session["user"]})
        if code == 201:
            result = body                       # contains the one-time password
        else:
            flash(body.get("error", "Onboarding failed"), "bad")
    return render_template("onboard.html", result=result)


@app.route("/offboard", methods=["GET", "POST"])
def offboard():
    if request.method == "POST":
        code, body = call("offboarding", "POST", "/offboard", json={
            "username": request.form.get("username"), "reason": request.form.get("reason", ""),
            "actor": session["user"]})
        if code == 200:
            flash(f"Offboarded {body['username']}: " + ", ".join(body["steps"]), "ok")
        else:
            flash(body.get("error", "Offboarding failed"), "bad")
        return redirect(url_for("offboard"))
    code, data = call("dashboard", "GET", "/api/employees", params={"refresh": 1})
    active = [e for e in data.get("employees", []) if e["status"] == "active"] if code == 200 else []
    if code != 200:
        flash(data.get("error", "Could not load employees"), "bad")
    return render_template("offboard.html", active=active)


@app.get("/dashboard")
def dashboard():
    code, data = call("dashboard", "GET", "/api/employees",
                      params={"refresh": 1} if request.args.get("refresh") else {})
    if code != 200:
        flash(data.get("error", "Dashboard service error"), "bad")
        data = {"summary": {}, "employees": [], "generated_at": ""}
    return render_template("dashboard.html", d=data)
