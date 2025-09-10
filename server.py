from flask import Flask, request, jsonify, render_template, redirect, url_for, session, g, abort
import sqlite3, os, json, datetime, hashlib, secrets
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

DB_PATH = os.environ.get("DB_PATH", "mydata.sqlite")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(16))
API_KEY_HEADER = "X-API-Key"

app = Flask(__name__)
app.secret_key = SECRET_KEY

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

def init_db():
    if not os.path.exists(DB_PATH):
        db = sqlite3.connect(DB_PATH)
        db.executescript(open("schema.sql").read())
        db.close()

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        if not session.get("is_admin"):
            abort(403)
        return f(*a, **kw)
    return w

def hash_api_key(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def verify_api_key(raw):
    h = hash_api_key(raw)
    db = get_db()
    row = db.execute("SELECT id, username, is_admin FROM users WHERE api_key_hash = ?", (h,)).fetchone()
    return dict(row) if row else None

@app.context_processor
def inject_user():
    if "user_id" in session:
        db = get_db()
        row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        return {"current_user": dict(row) if row else None}
    return {"current_user": None}

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    db = get_db()
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "").strip()
        if not u or not p:
            return render_template("register.html", error="missing")
        try:
            pwd = generate_password_hash(p)
            raw_api = secrets.token_urlsafe(32)
            akh = hash_api_key(raw_api)
            db.execute("INSERT INTO users (username, password_hash, api_key_hash, is_admin) VALUES (?, ?, ?, ?)",
                       (u, pwd, akh, 0))
            db.commit()
            return render_template("register.html", created=True, api_key=raw_api, username=u)
        except sqlite3.IntegrityError:
            return render_template("register.html", error="taken")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "").strip()
        row = db.execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
        if row and check_password_hash(row["password_hash"], p):
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["is_admin"] = bool(row["is_admin"])
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="invalid")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = session["user_id"]
    rows = db.execute("SELECT DISTINCT collection_name FROM documents WHERE owner_id = ? OR owner_id IS NULL", (uid,)).fetchall()
    collections = [r["collection_name"] for r in rows]
    key_row = db.execute("SELECT api_key_hash FROM users WHERE id = ?", (uid,)).fetchone()
    return render_template("dashboard.html", collections=collections, api_key_hash=key_row["api_key_hash"])

@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT id, username, is_admin, created_at FROM users").fetchall()
    cols = db.execute("SELECT DISTINCT collection_name FROM documents").fetchall()
    return render_template("admin.html", users=users, collections=[c["collection_name"] for c in cols])

@app.route("/collection/<name>")
@login_required
def collection(name):
    return render_template("collection.html", collection=name)

@app.route("/api/key/regenerate", methods=["POST"])
@login_required
def regen_key():
    db = get_db()
    uid = session["user_id"]
    raw = secrets.token_urlsafe(32)
    h = hash_api_key(raw)
    db.execute("UPDATE users SET api_key_hash = ? WHERE id = ?", (h, uid))
    db.commit()
    return jsonify({"api_key": raw})

@app.route("/api/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    db = get_db()
    body = request.get_json(force=True)
    u = body.get("username")
    p = body.get("password")
    is_admin = 1 if body.get("is_admin") else 0
    raw = secrets.token_urlsafe(32)
    try:
        db.execute("INSERT INTO users (username, password_hash, api_key_hash, is_admin) VALUES (?, ?, ?, ?)",
                   (u, generate_password_hash(p), hash_api_key(raw), is_admin))
        db.commit()
        return jsonify({"created": True, "api_key": raw})
    except sqlite3.IntegrityError:
        return jsonify({"created": False, "error": "exists"}), 400

def require_api_key_or_session():
    key = request.headers.get(API_KEY_HEADER) or request.args.get("api_key")
    if key:
        user = verify_api_key(key)
        if not user:
            abort(401)
        return user
    if "user_id" in session:
        db = get_db()
        row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        return dict(row)
    abort(401)

def enforce_data_type(data_type, payload):
    types = {
        "pair": {"required": ["key", "value"]},
        "four": {"required": ["a", "b", "c", "d"]}
    }
    spec = types.get(data_type)
    if not spec:
        return True, payload
    for r in spec["required"]:
        if r not in payload:
            return False, f"missing field {r}"
    return True, payload

@app.route("/api/operate", methods=["POST"])
def api_operate():
    user = require_api_key_or_session()
    body = request.get_json(force=True) or {}
    collection = body.get("collection")
    action = body.get("action")
    data_type = body.get("data_type")
    payload = body.get("payload", {})
    if not collection or not action:
        return jsonify({"error": "collection and action required"}), 400
    ok, val = enforce_data_type(data_type, payload) 
    if not ok:
        return jsonify({"error": val}), 400
    db = get_db()
    now = datetime.datetime.utcnow().isoformat()
    if action == "save":
        doc_text = json.dumps(payload)
        cur = db.execute("INSERT INTO documents (collection_name, doc_json, owner_id, data_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                         (collection, doc_text, user["id"], data_type, now, now))
        db.commit()
        return jsonify({"inserted_id": cur.lastrowid})
    if action == "read":
        flt = payload.get("filter", {})
        limit = int(payload.get("limit", 100))
        skip = int(payload.get("skip", 0))
        where = ["collection_name = ?"]
        params = [collection]
        for k, v in flt.items():
            where.append("json_extract(doc_json, ?) = ?")
            params.append(f"$.{k}")
            params.append(v if isinstance(v, (int, float)) else json.dumps(v))
        q = f"SELECT id, doc_json, owner_id, data_type, created_at, updated_at FROM documents WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, skip])
        rows = db.execute(q, params).fetchall()
        out = []
        for r in rows:
            d = json.loads(r["doc_json"])
            d["_id"] = r["id"]
            d["_owner_id"] = r["owner_id"]
            d["_data_type"] = r["data_type"]
            out.append(d)
        return jsonify(out)
    if action == "delete":
        if "id" in payload:
            cur = db.execute("DELETE FROM documents WHERE id = ? AND collection_name = ?", (payload["id"], collection))
            db.commit()
            return jsonify({"deleted": cur.rowcount})
        flt = payload.get("filter", {})
        where = ["collection_name = ?"]
        params = [collection]
        for k, v in flt.items():
            where.append("json_extract(doc_json, ?) = ?")
            params.append(f"$.{k}")
            params.append(v if isinstance(v, (int, float)) else json.dumps(v))
        row = db.execute(f"SELECT id FROM documents WHERE {' AND '.join(where)} LIMIT 1", params).fetchone()
        if not row:
            return jsonify({"deleted": 0})
        cur = db.execute("DELETE FROM documents WHERE id = ?", (row["id"],))
        db.commit()
        return jsonify({"deleted": cur.rowcount})
    return jsonify({"error": "unsupported action"}), 400

@app.route("/api/list_collections", methods=["GET"])
def api_list_collections():
    require_api_key_or_session()
    db = get_db()
    rows = db.execute("SELECT DISTINCT collection_name FROM documents").fetchall()
    return jsonify([r["collection_name"] for r in rows])

@app.route("/api/users", methods=["GET"])
def api_users():
    user = require_api_key_or_session()
    if not user.get("is_admin"):
        abort(403)
    db = get_db()
    rows = db.execute("SELECT id, username, is_admin, created_at FROM users").fetchall()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
