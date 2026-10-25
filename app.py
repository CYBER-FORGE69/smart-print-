"""Pay-per-print server: admin panel, QR upload form, page count, payment check, auto-print."""
import os, io, re, contextlib, hmac, hashlib, secrets, sqlite3, subprocess, sys, threading, time
from functools import wraps
import pyotp, qrcode, requests
from flask import (Flask, request, session, redirect, render_template, flash,
                   send_file, abort, jsonify, g, has_request_context)
from jinja2 import DictLoader
from cryptography.fernet import Fernet
from pypdf import PdfReader
from werkzeug.security import generate_password_hash as H, check_password_hash as C

BASE = os.path.dirname(os.path.abspath(__file__))
UP = os.path.join(BASE, "uploads"); os.makedirs(UP, exist_ok=True)
DB = os.path.join(BASE, "print.db")
app = Flask(__name__)
def keyfile(name, make):  # secrets live in owner-only files, never in the code
    p = os.path.join(BASE, name)
    if not os.path.exists(p):
        with os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f: f.write(make())
    return open(p).read().strip()
app.secret_key = os.environ.get("SECRET_KEY") or keyfile(".secret_key", lambda: secrets.token_hex(32))
FER = Fernet(keyfile(".enc_key", lambda: Fernet.generate_key().decode()).encode())
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1", PERMANENT_SESSION_LIFETIME=900)  # 15 min idle logout
if os.environ.get("PROXY") == "1":  # only set behind your own reverse proxy (nginx, Caddy, Cloudflare tunnel)
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
SETUP_TOKEN = os.environ.get("SETUP_TOKEN") or secrets.token_urlsafe(9)  # stops a stranger claiming the first admin
DUMMY = H("dummy-password-for-timing")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
SIGS = {b"%PDF": "pdf", b"\x89PNG": "png", b"\xff\xd8\xff": "jpg"}  # only PDF, PNG, JPG
DEFAULTS = {"printer": "", "price_paise": "200", "pay_mode": "mock", "public_url": "",
            "rzp_key": "", "rzp_secret": "", "rzp_webhook": "", "max_pages": "100"}
pin_fails = {}  # admin id -> (count, locked_until)

# ---------- database ----------
def db():
    c = sqlite3.connect(DB, timeout=10); c.row_factory = sqlite3.Row; c.execute("pragma journal_mode=wal"); return c
def q(sql, a=(), one=False, write=False):
    c = db()
    try:  # always close, even on errors, so a failed write can never leave the database locked
        cur = c.execute(sql, a); r = cur.fetchone() if one else cur.fetchall()
        if write: c.commit()
        n = cur.rowcount
    finally: c.close()
    return n if write else r
with contextlib.closing(db()) as c:
    c.executescript("""create table if not exists admins(id integer primary key, username text unique,
      pw_hash text, pin_hash text, totp_secret text, totp_on int default 0);
      create table if not exists settings(k text primary key, v text);
      create table if not exists jobs(id text primary key, filename text, path text, pages int,
      amount int, status text, created real, qr_url text);
      create table if not exists audit(ts real, who text, ip text, ev text);
      create table if not exists payments(pid text primary key);""")
try:
    with contextlib.closing(db()) as c: c.execute("alter table admins add column sv int default 0")
except sqlite3.OperationalError: pass
ENC = ("rzp_key", "rzp_secret", "rzp_webhook")  # payment secrets are encrypted in the database
def S(k):
    r = q("select v from settings where k=?", (k,), one=True)
    if not r: return DEFAULTS[k]
    if k in ENC and r["v"]:
        try: return FER.decrypt(r["v"].encode()).decode()
        except Exception: return ""
    return r["v"]
def setS(k, v):
    q("insert or replace into settings values(?,?)", (k, FER.encrypt(v.encode()).decode() if k in ENC and v else v), write=True)

# ---------- printing ----------
def printers():
    try: return subprocess.run(["lpstat", "-e"], capture_output=True, text=True, timeout=5).stdout.split()
    except Exception: return []
def print_file(path):
    if sys.platform.startswith("win"):
        os.startfile(path, "print")  # prints to the Windows default printer
    else:
        cmd = ["lp"] + (["-d", S("printer")] if S("printer") else []) + [path]
        subprocess.run(cmd, check=True, timeout=60)
def run_print(jid):
    j = q("select path from jobs where id=?", (jid,), one=True)
    q("update jobs set status='printing' where id=?", (jid,), write=True)
    try:
        if not j["path"]: raise FileNotFoundError("file already removed")
        print_file(j["path"]); st = "printed"
    except Exception as e: print("print failed:", e); st = "print_failed"; log(f"print failed job={jid}", "system")
    q("update jobs set status=? where id=?", (st, jid), write=True)

# ---------- payment ----------
def mark_paid(jid, paid, pid=None):
    j = q("select * from jobs where id=?", (jid,), one=True)
    if not j or int(paid) != j["amount"]:  # amount must match exactly
        log(f"payment rejected job={jid} paid={paid}", "system"); return False
    if pid:
        try: q("insert into payments values(?)", (pid,), write=True)
        except sqlite3.IntegrityError: return True  # same payment sent twice: ignore
    if q("update jobs set status='paid' where id=? and status='pending'", (jid,), write=True):
        log(f"payment accepted job={jid}", "system")
        threading.Thread(target=run_print, args=(jid,), daemon=True).start()
    elif j["status"] == "expired": log(f"PAID AFTER EXPIRY job={jid}: refund needed", "system")
    return True
def rzp_qr(jid, amount):  # one single-use, fixed-amount QR per job
    r = requests.post("https://api.razorpay.com/v1/payments/qr_codes", auth=(S("rzp_key"), S("rzp_secret")),
        json={"type": "upi_qr", "name": "Print " + jid[:6], "usage": "single_use", "fixed_amount": True,
              "payment_amount": amount, "description": "Print job", "notes": {"job_id": jid}}, timeout=15)
    r.raise_for_status(); return r.json()["image_url"]

# ---------- helpers ----------
def png(data):
    b = io.BytesIO(); qrcode.make(data).save(b, "PNG"); b.seek(0)
    return send_file(b, mimetype="image/png")
def me():
    a = q("select * from admins where id=?", (session.get("aid"),), one=True)
    if a and session.get("sv") != a["sv"]: session.clear(); return None  # password/code changed elsewhere
    return a
def bump(a):  # log out this admin's other sessions
    q("update admins set sv=sv+1 where id=?", (a["id"],), write=True)
    if session.get("aid") == a["id"]: session["sv"] = a["sv"] + 1
def log(ev, who=None):
    ip = request.remote_addr if has_request_context() else "-"
    q("insert into audit values(?,?,?,?)", (time.time(), who or (me() or {"username": "-"})["username"], ip, ev), write=True)
fails = {}
used = {}
def tsec(a):
    try: return FER.decrypt(a["totp_secret"].encode()).decode()
    except Exception: return a["totp_secret"]  # secret saved before encryption existed
def totp_ok(a, code):
    code = code.strip(); k = (a["id"], code)
    if time.time() - used.get(k, 0) < 120: return False  # each code works once
    if not pyotp.TOTP(tsec(a)).verify(code, valid_window=1): return False
    if len(used) > 1000: used.clear()
    used[k] = time.time(); return True
def locked(k): return time.time() < fails.get(k, (0, 0))[1]
def fail(k, limit=5, secs=600):
    if len(fails) > 10000: fails.clear()  # cap memory
    n = fails.get(k, (0, 0))[0] + 1; fails[k] = (n, time.time() + secs if n >= limit else 0)
WEAK = "Use a password with 10+ characters that mixes letters and numbers."
def weak(p): return len(p) < 10 or p.isalpha() or p.isdigit() or p.lower() in ("password123", "1234567890", "qwertyuiop")
def admin(f):
    @wraps(f)
    def w(*a, **k):
        if not me(): return redirect("/admin/login")
        if not me()["pin_hash"] and request.path != "/admin/pin": return redirect("/admin/pin")
        return f(*a, **k)
    return w
def pin_ok(a):
    n, until = pin_fails.get(a["id"], (0, 0))
    if time.time() < until: return False
    if a["pin_hash"] and C(a["pin_hash"], request.form.get("pin", "")):
        pin_fails.pop(a["id"], None); return True
    n += 1; pin_fails[a["id"]] = (n, time.time() + 300 if n >= 5 else 0); log("wrong security code", a["username"])
    flash("Wrong security code." if n < 5 else "Too many wrong codes. Try again in 5 minutes.", "err")
    return False
@app.context_processor
def ctx():
    a = me(); session.setdefault("csrf", secrets.token_hex(16))
    return {"csrf": session["csrf"], "S": S, "admin": a, "nonce": getattr(g, "nonce", "")}
@app.before_request
def csrf_check():
    if request.method == "POST" and request.path.startswith(("/admin", "/setup")) \
       and request.form.get("csrf") != session.get("csrf"): abort(400)

@app.before_request
def make_nonce(): g.nonce = secrets.token_urlsafe(16)
@app.after_request
def secure_headers(r):
    n = getattr(g, "nonce", "")
    r.headers["Content-Security-Policy"] = (f"default-src 'self'; img-src 'self' data: https:; style-src 'nonce-{n}'; "
        f"script-src 'nonce-{n}'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                      "Permissions-Policy": "camera=(), microphone=(), geolocation=()"})
    if request.path.startswith(("/admin", "/setup")): r.headers["Cache-Control"] = "no-store"
    if os.environ.get("HTTPS") == "1": r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r
def cleanup():  # delete uploaded files: unpaid after 1h, printed after 10 min, failed after 24h
    while True:
        now = time.time()
        for j in q("select id,path,status,created from jobs where path!=''"):
            age = now - j["created"]
            if (j["status"] == "pending" and age > 3600) or (j["status"] == "printed" and age > 600) or (j["status"] == "print_failed" and age > 86400):
                try: os.remove(j["path"])
                except OSError: pass
                q("update jobs set path='', status=? where id=?", ("expired" if j["status"] == "pending" else j["status"], j["id"]), write=True)
        time.sleep(300)

# ---------- public: upload form + payment ----------
uploads = {}
@app.route("/", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        now = time.time(); ts = [t for t in uploads.get(request.remote_addr, []) if now - t < 600]
        if len(ts) >= 10: flash("Too many uploads. Wait a few minutes and try again.", "err"); return redirect("/")
        if len(uploads) > 10000: uploads.clear()
        uploads[request.remote_addr] = ts + [now]
        f = request.files.get("file")
        if not f or not f.filename: flash("Choose a file to upload.", "err"); return redirect("/")
        kind = next((v for sg, v in SIGS.items() if f.stream.read(4).startswith(sg)), None); f.stream.seek(0)
        ext = f.filename.rsplit(".", 1)[-1].lower()
        if not kind or ext not in ("pdf", "png", "jpg", "jpeg"):
            flash("Only PDF, PNG and JPG files are accepted.", "err"); return redirect("/")
        jid = secrets.token_urlsafe(12); path = os.path.join(UP, f"{jid}.{kind}"); f.save(path)
        try:
            pages = 1
            if kind == "pdf":
                if re.search(rb"/(JavaScript|JS|Launch|EmbeddedFile)\b", open(path, "rb").read()): raise ValueError("active content")
                rd = PdfReader(path)
                if rd.is_encrypted: raise ValueError("password protected")
                pages = len(rd.pages)
            if not 1 <= pages <= int(S("max_pages")): raise ValueError("page limit")
        except Exception as e:
            os.remove(path); log(f"upload rejected: {e}", "visitor")
            flash(f"This file can't be accepted. Use a PDF without a password or active content, up to {S('max_pages')} pages.", "err"); return redirect("/")
        amount = pages * int(S("price_paise")); qr = ""
        if S("pay_mode") == "razorpay":
            try: qr = rzp_qr(jid, amount)
            except Exception: os.remove(path); flash("Payment is unavailable right now. Please tell the operator.", "err"); return redirect("/")
        q("insert into jobs values(?,?,?,?,?,?,?,?)", (jid, f.filename[:120], path, pages, amount, "pending", time.time(), qr), write=True)
        return redirect(f"/pay/{jid}")
    return render_template("upload.html")
@app.route("/pay/<jid>")
def pay(jid):
    j = q("select * from jobs where id=?", (jid,), one=True) or abort(404)
    return render_template("pay.html", j=j)
@app.route("/pay/<jid>/qr.png")
def pay_qr(jid): return png(request.url_root + f"pay/{jid}")  # mock mode only
@app.route("/status/<jid>")
def status(jid):
    j = q("select status from jobs where id=?", (jid,), one=True) or abort(404)
    return jsonify(status=j["status"])
@app.route("/mock-pay/<jid>", methods=["POST"])
def mock_pay(jid):
    if S("pay_mode") != "mock" or not me() or request.form.get("csrf") != session.get("csrf"): abort(404)  # admin-only test button
    j = q("select amount from jobs where id=?", (jid,), one=True) or abort(404)
    mark_paid(jid, j["amount"]); return redirect(f"/pay/{jid}")
@app.route("/webhook/razorpay", methods=["POST"])
def webhook():
    raw = request.get_data(); sig = request.headers.get("X-Razorpay-Signature", "")
    good = hmac.new(S("rzp_webhook").encode(), raw, hashlib.sha256).hexdigest()
    if not S("rzp_webhook") or not hmac.compare_digest(good, sig): abort(400)
    d = request.get_json()
    if d.get("event") == "qr_code.credited":
        p = d["payload"]; notes = p["qr_code"]["entity"].get("notes") or {}
        jid = notes.get("job_id") if isinstance(notes, dict) else None
        if jid: mark_paid(jid, p["payment"]["entity"]["amount"], p["payment"]["entity"]["id"])
    return "ok"

# ---------- admin ----------
@app.route("/setup", methods=["GET", "POST"])
def setup():
    if q("select 1 from admins", one=True): abort(404)
    if request.method == "POST":
        if not hmac.compare_digest(request.form.get("setup_code", ""), SETUP_TOKEN):
            log("wrong setup code", "visitor"); flash("Wrong setup code. It is printed in the server console.", "err"); return render_template("setup.html")
        if weak(request.form["password"]): flash(WEAK, "err"); return render_template("setup.html")
        q("insert into admins(username,pw_hash) values(?,?)", (request.form["username"].strip(), H(request.form["password"])), write=True)
        a = q("select * from admins", one=True); session.clear(); session.permanent = True
        session["aid"] = a["id"]; session["sv"] = a["sv"]; log("first admin created", a["username"]); return redirect("/admin/pin")
    return render_template("setup.html")
@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if not q("select 1 from admins", one=True): return redirect("/setup")
    if request.method == "POST":
        u = request.form["username"].strip(); k = ("login", request.remote_addr, u.lower())
        if locked(k): flash("Too many attempts. Try again in 10 minutes.", "err"); return render_template("login.html")
        a = q("select * from admins where username=?", (u,), one=True)
        good = C(a["pw_hash"] if a else DUMMY, request.form["password"])  # same work whether or not the user exists
        if a and good:
            fails.pop(k, None); session.clear(); session.permanent = True
            if a["totp_on"]: session["pre"] = a["id"]; return redirect("/admin/totp")
            session["aid"] = a["id"]; session["sv"] = a["sv"]; log("login", a["username"]); return redirect("/admin")
        fail(k); log("login failed: " + u[:40], "visitor"); flash("Wrong username or password.", "err")
    return render_template("login.html")
@app.route("/admin/totp", methods=["GET", "POST"])
def totp():
    a = q("select * from admins where id=?", (session.get("pre"),), one=True) or abort(403)
    k = ("totp", a["id"])
    if request.method == "POST":
        if locked(k): flash("Too many wrong codes. Try again in 10 minutes.", "err"); return render_template("totp.html")
        if totp_ok(a, request.form["code"]):
            fails.pop(k, None); session.pop("pre"); session["aid"] = a["id"]; session["sv"] = a["sv"]
            log("login (2FA)", a["username"]); return redirect("/admin")
        fail(k); log("wrong 2FA code", a["username"]); flash("That code didn't match. Try the newest code.", "err")
    return render_template("totp.html")
@app.route("/admin/logout", methods=["POST"])
def logout():
    log("logout"); session.clear(); return redirect("/admin/login")
@app.route("/admin")
@admin
def dash():
    return render_template("admin.html", printers=printers(), admins=q("select id,username from admins"),
        jobs=q("select * from jobs order by created desc limit 15"),
        audit=[(time.strftime("%d %b %H:%M", time.localtime(r["ts"])), r["who"], r["ip"], r["ev"]) for r in q("select * from audit order by ts desc limit 15")], pending2fa=bool(me()["totp_secret"] and not me()["totp_on"]))
@app.route("/admin/form-qr.png")
@admin
def form_qr(): return png((S("public_url") or request.url_root).rstrip("/") + "/")
@app.route("/admin/pin", methods=["GET", "POST"])
@admin
def pin():
    a = me()
    if request.method == "POST":
        if a["pin_hash"] and not pin_ok(a): return redirect("/admin/pin")
        new = request.form["new_pin"]
        if len(new) < 6: flash("Use at least 6 characters.", "err"); return redirect("/admin/pin")
        q("update admins set pin_hash=? where id=?", (H(new), a["id"]), write=True); bump(a); log("security code changed")
        flash("Security code saved.", "ok"); return redirect("/admin")
    return render_template("pin.html")
@app.route("/admin/printer", methods=["POST"])
@admin
def set_printer():
    setS("printer", request.form.get("printer", "")); setS("public_url", request.form.get("public_url", "").strip())
    try: setS("max_pages", str(min(500, max(1, int(request.form.get("max_pages", 100))))))
    except ValueError: pass
    log("printer settings changed"); flash("Printer settings saved.", "ok"); return redirect("/admin")
@app.route("/admin/payment", methods=["POST"])
@admin
def set_payment():
    if not pin_ok(me()): return redirect("/admin")
    try: price = round(float(request.form["price"]) * 100)  # round, not int(): 2.3*100 is 229.999...
    except ValueError: price = 0
    if price < 1 or request.form["mode"] not in ("mock", "razorpay"): flash("Enter a valid price and mode.", "err"); return redirect("/admin")
    setS("price_paise", str(price)); setS("pay_mode", request.form["mode"])
    for k in ("rzp_key", "rzp_secret", "rzp_webhook"):
        if request.form.get(k): setS(k, request.form[k].strip())  # blank = keep current
    log("payment settings changed"); flash("Payment settings saved.", "ok"); return redirect("/admin")
@app.route("/admin/account", methods=["POST"])
@admin
def account():
    a = me()
    if not pin_ok(a): return redirect("/admin")
    pw = request.form.get("password")
    if pw and weak(pw): flash(WEAK, "err"); return redirect("/admin")
    try:
        if request.form.get("username"): q("update admins set username=? where id=?", (request.form["username"].strip(), a["id"]), write=True)
    except sqlite3.IntegrityError: flash("That username is taken.", "err"); return redirect("/admin")
    if pw: q("update admins set pw_hash=? where id=?", (H(pw), a["id"]), write=True); bump(a)
    log("account updated"); flash("Account updated.", "ok"); return redirect("/admin")
@app.route("/admin/admins", methods=["POST"])
@admin
def add_admin():
    if not pin_ok(me()): return redirect("/admin")
    if weak(request.form["password"]): flash(WEAK, "err"); return redirect("/admin")
    try: q("insert into admins(username,pw_hash) values(?,?)", (request.form["username"].strip(), H(request.form["password"])), write=True)
    except sqlite3.IntegrityError: flash("That username is taken.", "err"); return redirect("/admin")
    log("admin added: " + request.form["username"].strip()[:40]); flash("Admin added. They set their own security code at first login.", "ok"); return redirect("/admin")
@app.route("/admin/retry/<jid>", methods=["POST"])
@admin
def retry(jid):
    j = q("select status,path from jobs where id=?", (jid,), one=True)
    if j and j["status"] == "print_failed" and j["path"]:
        log(f"print retried job={jid}"); threading.Thread(target=run_print, args=(jid,), daemon=True).start()
    return redirect("/admin")
@app.route("/admin/2fa/start", methods=["POST"])
@admin
def tfa_start():
    q("update admins set totp_secret=?, totp_on=0 where id=?", (FER.encrypt(pyotp.random_base32().encode()).decode(), me()["id"]), write=True); return redirect("/admin")
@app.route("/admin/2fa.png")
@admin
def tfa_png(): return png(pyotp.TOTP(tsec(me())).provisioning_uri(me()["username"], issuer_name="Print Admin"))
@app.route("/admin/2fa/confirm", methods=["POST"])
@admin
def tfa_confirm():
    if totp_ok(me(), request.form["code"]):
        q("update admins set totp_on=1 where id=?", (me()["id"],), write=True); log("2FA on"); flash("Two-step login is on.", "ok")
    else: flash("That code didn't match.", "err")
    return redirect("/admin")
@app.route("/admin/2fa/off", methods=["POST"])
@admin
def tfa_off():
    if pin_ok(me()): q("update admins set totp_on=0, totp_secret=NULL where id=?", (me()["id"],), write=True); log("2FA off"); flash("Two-step login is off.", "ok")
    return redirect("/admin")

# ---------- templates ----------
def T(body, title): return "{% extends 'base.html' %}{% block t %}" + title + "{% endblock %}{% block b %}" + body + "{% endblock %}"
PIN_FIELD = '<input type=hidden name=pin>'
CS = '<input type=hidden name=csrf value="{{csrf}}">'
app.jinja_loader = DictLoader({
"base.html": """<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{% block t %}{% endblock %}</title><style nonce="{{nonce}}">
:root{--ink:#1c2321;--bg:#f6f8f7;--acc:#0f6b5c;--line:#d5dcd9}*{box-sizing:border-box}
body{font:16px/1.5 system-ui,sans-serif;margin:0;background:var(--bg);color:var(--ink)}main{max-width:720px;margin:0 auto;padding:24px 16px}
h1{font-size:1.6rem;margin:.2em 0 .6em}h2{font-size:1.1rem;margin:0 0 .6em}section{background:#fff;border:1px solid var(--line);border-radius:8px;padding:16px;margin:0 0 16px}
label{display:block;margin:.6em 0 .2em;font-weight:600}input,select{width:100%;padding:10px;border:1px solid var(--line);border-radius:6px;font:inherit}
button{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:10px 16px;font:inherit;cursor:pointer;margin-top:12px}
button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #7fd1c2;outline-offset:2px}
.ok,.err{padding:10px;border-radius:6px;margin-bottom:12px;background:#e3f3ef}.err{background:#fbe4e4}img.qr{max-width:260px;width:100%}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px;border-bottom:1px solid var(--line)}dialog{border:1px solid var(--line);border-radius:8px}.gray{background:#555}
</style><main>{% for c,m in get_flashed_messages(with_categories=true) %}<div class={{c}}>{{m}}</div>{% endfor %}{% block b %}{% endblock %}</main>
<dialog id=pinbox><form method=dialog><label for=pinin>Enter your security code</label><input id=pinin type=password autocomplete=off>
<button value=ok>Confirm</button> <button value=cancel class=gray>Cancel</button></form></dialog>
<script nonce="{{nonce}}">document.querySelectorAll('form.sens').forEach(f=>f.addEventListener('submit',e=>{if(f.dataset.ok)return;e.preventDefault();
const d=document.getElementById('pinbox'),i=document.getElementById('pinin');d.onclose=()=>{if(d.returnValue==='ok'){f.querySelector('[name=pin]').value=i.value;f.dataset.ok=1;f.submit()}i.value=''};d.showModal();i.focus()}))</script></html>""",
"upload.html": T("""<h1>Print a file</h1><section><form method=post enctype=multipart/form-data><label for=f>PDF, PNG or JPG (max 25 MB)</label>
<input id=f type=file name=file accept=".pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg" required><button>Count pages and get price</button></form>
<p>Price: ₹{{'%.2f'|format(S('price_paise')|int/100)}} per page.</p></section>""", "Print"),
"pay.html": T("""<h1>Pay to print</h1><section><p><b>{{j.filename}}</b><br>{{j.pages}} page(s) &times; ₹{{'%.2f'|format(S('price_paise')|int/100)}} = <b>₹{{'%.2f'|format(j.amount/100)}}</b></p>
{% if j.status=='pending' %}<div id=qrbox><img class=qr src="{{ j.qr_url or '/pay/'+j.id+'/qr.png' }}" alt="Payment QR for this file only"><p>Scan with any UPI app and pay exactly ₹{{'%.2f'|format(j.amount/100)}}. Printing starts after payment is confirmed.</p>
{% if S('pay_mode')=='mock' and admin %}<form method=post action="/mock-pay/{{j.id}}"><input type=hidden name=csrf value="{{csrf}}"><button>Test mode: simulate payment</button></form>{% endif %}</div>{% endif %}
<p id=st aria-live=polite>Status: {{j.status}}</p></section>
<script nonce="{{nonce}}">const L={pending:'Waiting for payment',paid:'Paid. Sending to printer',printing:'Printing now',printed:'Done. Collect your pages',print_failed:'Paid, but printing failed. Tell the operator',expired:'This job expired. Upload the file again'};
async function p(){const r=await (await fetch('/status/{{j.id}}')).json();document.getElementById('st').textContent=L[r.status]||r.status;if(r.status!='pending'){const b=document.getElementById('qrbox');if(b)b.remove()}if(!['printed','print_failed','expired'].includes(r.status))setTimeout(p,3000)}p()</script>""", "Pay"),
"setup.html": T("<h1>Create the first admin</h1><section><form method=post>" + CS + """<label for=sc>Setup code (printed in the server console)</label><input id=sc name=setup_code autocomplete=off required><label for=u>Username</label><input id=u name=username required>
<label for=p>Password</label><input id=p name=password type=password minlength=10 required><button>Create admin</button></form></section>""", "Setup"),
"login.html": T("<h1>Admin login</h1><section><form method=post>" + CS + """<label for=u>Username</label><input id=u name=username required>
<label for=p>Password</label><input id=p name=password type=password required><button>Log in</button></form></section>""", "Login"),
"totp.html": T("<h1>Two-step login</h1><section><form method=post>" + CS + """<label for=c>Code from your authenticator app</label>
<input id=c name=code inputmode=numeric autocomplete=one-time-code required><button>Verify</button></form></section>""", "Verify"),
"pin.html": T("<h1>Security code</h1><section><p>This PIN or password protects payment settings and account changes. Only you know it.</p><form method=post>" + CS + """
{% if admin.pin_hash %}<label for=o>Current code</label><input id=o name=pin type=password required>{% endif %}
<label for=n>New code (6+ characters)</label><input id=n name=new_pin type=password minlength=6 required><button>Save security code</button></form></section>""", "Security code"),
"admin.html": T("""<h1>Admin: {{admin.username}}</h1>
<section><h2>Printer</h2><form method=post action=/admin/printer>""" + CS + """<label for=pr>Printer</label><select id=pr name=printer><option value="">System default</option>
{% for p in printers %}<option {{'selected' if p==S('printer')}}>{{p}}</option>{% endfor %}</select>
<label for=pu>Public address (used in the form QR)</label><input id=pu name=public_url value="{{S('public_url')}}" placeholder="https://print.example.com"><label for=mp>Max pages per job</label><input id=mp name=max_pages type=number min=1 max=500 value="{{S('max_pages')}}"><button>Save printer settings</button></form></section>
<section><h2>Form QR code</h2><img class=qr src=/admin/form-qr.png alt="QR code that opens the upload form"></section>
<section><h2>Payment settings</h2><form method=post action=/admin/payment class=sens>""" + CS + PIN_FIELD + """<label for=pp>Price per page (₹)</label><input id=pp name=price type=number step=0.01 min=0.01 value="{{S('price_paise')|int/100}}">
<label for=m>Mode</label><select id=m name=mode><option value=mock {{'selected' if S('pay_mode')=='mock'}}>Test (no real payment)</option><option value=razorpay {{'selected' if S('pay_mode')=='razorpay'}}>Razorpay UPI QR</option></select>
<label for=k1>Razorpay key id (blank keeps current)</label><input id=k1 name=rzp_key><label for=k2>Razorpay key secret</label><input id=k2 name=rzp_secret type=password>
<label for=k3>Webhook secret</label><input id=k3 name=rzp_webhook type=password><button>Save payment settings</button></form></section>
<section><h2>Your account</h2><form method=post action=/admin/account class=sens>""" + CS + PIN_FIELD + """<label for=nu>New username</label><input id=nu name=username value="{{admin.username}}">
<label for=np>New password (blank keeps current)</label><input id=np name=password type=password minlength=10><button>Save account changes</button></form>
<p><a href=/admin/pin>Change security code</a></p></section>
<section><h2>Two-step login</h2>{% if admin.totp_on %}<form method=post action=/admin/2fa/off class=sens>""" + CS + PIN_FIELD + """<button>Turn off</button></form>
{% elif pending2fa %}<img class=qr src=/admin/2fa.png alt="Authenticator QR"><form method=post action=/admin/2fa/confirm>""" + CS + """<label for=tc>Enter the 6-digit code</label><input id=tc name=code required><button>Turn on</button></form>
{% else %}<form method=post action=/admin/2fa/start>""" + CS + """<button>Set up two-step login</button></form>{% endif %}</section>
<section><h2>Admins</h2><table>{% for a in admins %}<tr><td>{{a.username}}</td></tr>{% endfor %}</table>
<form method=post action=/admin/admins class=sens>""" + CS + PIN_FIELD + """<label for=au>New admin username</label><input id=au name=username required>
<label for=ap>Temporary password</label><input id=ap name=password type=password minlength=10 required><button>Add admin</button></form></section>
<section><h2>Recent jobs</h2><table><tr><th>File<th>Pages<th>₹<th>Status<th></tr>{% for j in jobs %}<tr><td>{{j.filename}}<td>{{j.pages}}<td>{{'%.2f'|format(j.amount/100)}}<td>{{j.status}}<td>{% if j.status=='print_failed' and j.path %}<form method=post action="/admin/retry/{{j.id}}"><input type=hidden name=csrf value="{{csrf}}"><button>Retry</button></form>{% endif %}</tr>{% endfor %}</table></section>
<section><h2>Security log</h2><table><tr><th>Time<th>Who<th>IP<th>Event</tr>{% for t,w,i,e in audit %}<tr><td>{{t}}<td>{{w}}<td>{{i}}<td>{{e}}</tr>{% endfor %}</table></section>
<form method=post action=/admin/logout>""" + CS + "<button>Log out</button></form>", "Admin"),
})
if not q("select 1 from admins", one=True): print(f"\n*** First-time setup code: {SETUP_TOKEN} ***\n")
if __name__ == "__main__":
    threading.Thread(target=cleanup, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
