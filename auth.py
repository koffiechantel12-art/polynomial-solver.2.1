import sqlite3, hashlib, os, re, importlib.util
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "data.db")
PASSWORD_EXPIRY_DAYS = 90
_SUPABASE_CLIENT = None
_SUPABASE_CONFIG = {"url": None, "key": None}

def _supabase_config():
    url = os.environ.get("SUPABASE_URL") or os.environ.get("NEXT_PUBLIC_SUPABASE_URL")
    key = (
        os.environ.get("SUPABASE_SERVICE_KEY")
        or os.environ.get("SUPABASE_KEY")
        or os.environ.get("SUPABASE_ANON_KEY")
        or os.environ.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_DEFAULT_KEY")
    )
    if not (url and key) and importlib.util.find_spec("streamlit"):
        import streamlit as st
        url = url or st.secrets.get("SUPABASE_URL") or st.secrets.get("NEXT_PUBLIC_SUPABASE_URL")
        key = (
            key
            or st.secrets.get("SUPABASE_SERVICE_KEY")
            or st.secrets.get("SUPABASE_KEY")
            or st.secrets.get("SUPABASE_ANON_KEY")
            or st.secrets.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_DEFAULT_KEY")
        )
    return url, key

def _use_supabase():
    url, key = _supabase_config()
    return bool(url and key)

def _supabase():
    global _SUPABASE_CLIENT
    url, key = _supabase_config()
    if _SUPABASE_CLIENT is None or _SUPABASE_CONFIG["url"] != url or _SUPABASE_CONFIG["key"] != key:
        from supabase import create_client
        _SUPABASE_CLIENT = create_client(url, key)
        _SUPABASE_CONFIG["url"] = url
        _SUPABASE_CONFIG["key"] = key
    return _SUPABASE_CLIENT

def _supabase_insert(table, payload, fallback_payload=None):
    sb = _supabase()
    response = sb.table(table).insert(payload).execute()
    if getattr(response, "error", None) and fallback_payload:
        response = sb.table(table).insert(fallback_payload).execute()
    return response

def _supabase_select(table, select_clause, fallback_clause=None):
    sb = _supabase()
    response = sb.table(table).select(select_clause).execute()
    if getattr(response, "error", None) and fallback_clause:
        response = sb.table(table).select(fallback_clause).execute()
    return response

def _role_from_row(row):
    role = (row.get("role") or "").strip().lower()
    if role:
        return role
    return "admin" if row.get("is_admin") else "user"

def _conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    if _use_supabase():
        sb = _supabase()
        admin_user = os.environ.get("ADMIN_USERNAME", "ad")
        admin_pw = os.environ.get("ADMIN_PASSWORD", "ad")
        existing = (
            sb.table("users")
            .select("id,password,is_admin,role")
            .eq("username", admin_user)
            .limit(1)
            .execute()
        )
        if getattr(existing, "error", None):
            existing = (
                sb.table("users")
                .select("id,password,is_admin")
                .eq("username", admin_user)
                .limit(1)
                .execute()
            )
        h = hashlib.sha256(admin_pw.encode('utf-8')).hexdigest()
        if not existing.data:
            now = datetime.utcnow().isoformat()
            payload = {
                "username": admin_user,
                "password": h,
                "is_admin": 1,
                "role": "admin",
                "created_at": now,
                "password_last_changed": now,
                "must_set_recovery": 0
            }
            fallback = {
                "username": admin_user,
                "password": h,
                "is_admin": 1
            }
            _supabase_insert("users", payload, fallback)
        else:
            row = existing.data[0]
            needs_reset = row.get("password") != h or not bool(row.get("is_admin")) or _role_from_row(row) != "admin"
            if needs_reset:
                sb.table("users").update({
                    "password": h,
                    "is_admin": 1,
                    "role": "admin"
                }).eq("username", admin_user).execute()
        return

    conn = _conn(); c = conn.cursor()
    # ensure base users table exists (minimal columns)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0
    )""")
    # add any missing columns safely
    c.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in c.fetchall()]
    if "recovery_q" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN recovery_q TEXT")
    if "recovery_a" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN recovery_a TEXT")
    if "created_at" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN created_at DATETIME")
        c.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    if "must_set_recovery" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN must_set_recovery INTEGER DEFAULT 0")
        c.execute("UPDATE users SET must_set_recovery = 0 WHERE must_set_recovery IS NULL")
    if "phone" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN phone TEXT")
        try:
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_unique ON users(phone)")
        except Exception:
            pass
    if "password_last_changed" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN password_last_changed TEXT")
        c.execute(
            "UPDATE users SET password_last_changed = created_at "
            "WHERE password_last_changed IS NULL"
        )

    if "password_expired" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN password_expired INTEGER DEFAULT 0")

    if "role" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        c.execute("UPDATE users SET role='admin' WHERE is_admin=1 AND (role IS NULL OR role='')")

    # ensure history table exists
    c.execute("""CREATE TABLE IF NOT EXISTS history(
        id INTEGER PRIMARY KEY, username TEXT, expression TEXT, roots TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()

    # ensure single admin account using environment variables (secure in deployment)
    admin_user = os.environ.get("ADMIN_USERNAME", "ad")
    admin_pw = os.environ.get("ADMIN_PASSWORD", "ad")
    c.execute("SELECT password, is_admin, role FROM users WHERE username=?", (admin_user,))
    row = c.fetchone()
    h = hashlib.sha256(admin_pw.encode('utf-8')).hexdigest()
    if not row:
        now = datetime.utcnow().isoformat()
        c.execute(
            """
            INSERT INTO users(
                username, password, is_admin, role,
                created_at, password_last_changed, must_set_recovery
            )
            VALUES (?,?,?,?,?,?,0)
            """,
            (admin_user, h, 1, "admin", now, now)
        )
        conn.commit()
    else:
        pw_hash, is_admin, role = row
        if pw_hash != h or not bool(is_admin) or (role or "").strip().lower() != "admin":
            c.execute(
                "UPDATE users SET password=?, is_admin=1, role='admin' WHERE username=?",
                (h, admin_user)
            )
            conn.commit()

    conn.close()


def is_password_expired(password_last_changed):
    if not password_last_changed:
        return False
    try:
        last = datetime.fromisoformat(password_last_changed)
    except ValueError:
        return False
    return (datetime.utcnow() - last).days >= PASSWORD_EXPIRY_DAYS


def hash_pw(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def create_user(username, password, recovery_q=None, recovery_a=None, phone=None, role="user"):
    if _use_supabase():
        sb = _supabase()
        if phone:
            phone_check = sb.table("users").select("id").eq("phone", phone).limit(1).execute()
            if phone_check.data:
                return False
        now = datetime.utcnow().isoformat()
        role_value = (role or "user").strip().lower()
        payload = {
            "username": username,
            "password": hash_pw(password),
            "recovery_q": recovery_q,
            "recovery_a": hash_pw(recovery_a) if recovery_a else None,
            "role": role_value,
            "created_at": now,
            "password_last_changed": now,
            "must_set_recovery": 0,
            "phone": phone
        }
        fallback = {
            "username": username,
            "password": hash_pw(password),
            "is_admin": 1 if role_value == "admin" else 0
        }
        response = _supabase_insert("users", payload, fallback)
        return bool(response.data)
    conn = _conn()
    c = conn.cursor()
    try:
        if phone:
            c.execute("SELECT 1 FROM users WHERE phone=?", (phone,))
            if c.fetchone():
                return False

        now = datetime.utcnow().isoformat()

        role_value = (role or "user").strip().lower()
        c.execute("""
            INSERT INTO users(
                username, password,
                recovery_q, recovery_a,
                created_at, password_last_changed,
                must_set_recovery, phone, role, is_admin
            )
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            username,
            hash_pw(password),
            recovery_q,
            hash_pw(recovery_a) if recovery_a else None,
            now,
            now,
            0,
            phone,
            role_value,
            1 if role_value == "admin" else 0
        ))

        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()

def admin_create_user(username, password, phone=None, role="user"):
    if _use_supabase():
        sb = _supabase()
        if phone:
            phone_check = sb.table("users").select("id").eq("phone", phone).limit(1).execute()
            if phone_check.data:
                return False
        now = datetime.utcnow().isoformat()
        role_value = (role or "user").strip().lower()
        payload = {
            "username": username,
            "password": hash_pw(password),
            "role": role_value,
            "created_at": now,
            "password_last_changed": now,
            "must_set_recovery": 1,
            "phone": phone
        }
        fallback = {
            "username": username,
            "password": hash_pw(password),
            "is_admin": 1 if role_value == "admin" else 0
        }
        response = _supabase_insert("users", payload, fallback)
        return bool(response.data)
    conn = _conn()
    c = conn.cursor()
    try:
        if phone:
            c.execute("SELECT 1 FROM users WHERE phone=?", (phone,))
            if c.fetchone():
                return False

        now = datetime.utcnow().isoformat()

        role_value = (role or "user").strip().lower()
        c.execute("""
            INSERT INTO users(
                username, password,
                created_at, password_last_changed,
                must_set_recovery, phone, role, is_admin
            )
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            username,
            hash_pw(password),
            now,
            now,
            1,
            phone,
            role_value,
            1 if role_value == "admin" else 0
        ))

        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def verify_user(identifier, password):
    if _use_supabase():
        sb = _supabase()
        response = (
            sb.table("users")
            .select("username,password,is_admin,password_last_changed")
            .or_(f"username.eq.{identifier},phone.eq.{identifier}")
            .limit(1)
            .execute()
        )
        if not response.data:
            return None
        row = response.data[0]
        if row["password"] != hash_pw(password):
            return None
        if is_password_expired(row.get("password_last_changed")):
            return "EXPIRED"
        return {"username": row["username"], "is_admin": bool(row.get("is_admin"))}
    conn = _conn()
    c = conn.cursor()

    c.execute("""
        SELECT username, password, is_admin, password_last_changed
        FROM users
        WHERE username=? OR phone=?
    """, (identifier, identifier))

    row = c.fetchone()
    conn.close()

    if not row:
        return None

    username, pw_hash, is_admin, last_changed = row

    if pw_hash != hash_pw(password):
        return None

    if is_password_expired(last_changed):
        return "EXPIRED"

    return {"username": username, "is_admin": bool(is_admin)}


def get_user(identifier):
    if _use_supabase():
        sb = _supabase()
        response = (
            sb.table("users")
            .select("username,is_admin,role,recovery_q,recovery_a,must_set_recovery,phone")
            .or_(f"username.eq.{identifier},phone.eq.{identifier}")
            .limit(1)
            .execute()
        )
        if getattr(response, "error", None):
            response = (
                sb.table("users")
                .select("username,is_admin,recovery_q,recovery_a,must_set_recovery,phone")
                .or_(f"username.eq.{identifier},phone.eq.{identifier}")
                .limit(1)
                .execute()
            )
        if not response.data:
            return None
        row = response.data[0]
        return {
            "username": row.get("username"),
            "is_admin": bool(row.get("is_admin")),
            "role": _role_from_row(row),
            "recovery_q": row.get("recovery_q"),
            "recovery_a": row.get("recovery_a"),
            "must_set_recovery": bool(row.get("must_set_recovery")),
            "phone": row.get("phone")
        }
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT username,is_admin,role,recovery_q,recovery_a,must_set_recovery,phone FROM users WHERE username=? OR phone=?", (identifier, identifier))
    row = c.fetchone(); conn.close()
    if not row:
        return None
    role_value = (row[2] or "").strip().lower() or ("admin" if row[1] else "user")
    return {"username": row[0], "is_admin": bool(row[1]), "role": role_value, "recovery_q": row[3], "recovery_a": row[4], "must_set_recovery": bool(row[5]), "phone": row[6]}

def list_users():
    if _use_supabase():
        response = _supabase_select("users", "username,is_admin,role", "username,is_admin")
        return [{
            "username": r["username"],
            "is_admin": bool(r.get("is_admin")),
            "role": _role_from_row(r)
        } for r in response.data or []]
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT username,is_admin,role FROM users")
    users = [{
        "username": r[0],
        "is_admin": bool(r[1]),
        "role": (r[2] or "").strip().lower() or ("admin" if r[1] else "user")
    } for r in c.fetchall()]
    conn.close()
    return users

def search_users(q):
    if _use_supabase():
        response = _supabase_select("users", "username,is_admin,role", "username,is_admin")
        rows = response.data or []
        rows = [r for r in rows if q.lower() in (r.get("username") or "").lower()]
        return [{
            "username": r["username"],
            "is_admin": bool(r.get("is_admin")),
            "role": _role_from_row(r)
        } for r in rows][:200]
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT username,is_admin,role FROM users WHERE username LIKE ? ORDER BY username LIMIT 200", (f"%{q}%",))
    users = [{
        "username": r[0],
        "is_admin": bool(r[1]),
        "role": (r[2] or "").strip().lower() or ("admin" if r[1] else "user")
    } for r in c.fetchall()]
    conn.close()
    return users

def delete_user(username):
    # protect the admin 'ad' account
    if username == "ad":
        return False
    if _use_supabase():
        sb = _supabase()
        response = sb.table("users").delete().eq("username", username).execute()
        return bool(response.data)
    conn = _conn(); c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    changed = conn.total_changes
    conn.commit(); conn.close()
    return changed > 0

def set_role(username, role):
    if username == "ad":
        role_value = "admin"
    else:
        role_value = (role or "user").strip().lower()
    is_admin = 1 if role_value == "admin" else 0
    if _use_supabase():
        sb = _supabase()
        response = (
            sb.table("users")
            .update({"role": role_value, "is_admin": is_admin})
            .eq("username", username)
            .execute()
        )
        return bool(response.data)
    conn = _conn(); c = conn.cursor()
    c.execute("UPDATE users SET role=?, is_admin=? WHERE username=?", (role_value, is_admin, username))
    conn.commit(); ok = c.rowcount > 0
    conn.close()
    return ok

def set_recovery(username, question, answer):
    if _use_supabase():
        sb = _supabase()
        response = (
            sb.table("users")
            .update({
                "recovery_q": question,
                "recovery_a": hash_pw(answer),
                "must_set_recovery": 0
            })
            .eq("username", username)
            .execute()
        )
        return bool(response.data)
    conn = _conn(); c = conn.cursor()
    c.execute("UPDATE users SET recovery_q=?, recovery_a=?, must_set_recovery=0 WHERE username=?", (question, hash_pw(answer), username))
    conn.commit(); ok = c.rowcount > 0
    conn.close()
    return ok

def recover_password(username, answer, new_password):
    if _use_supabase():
        sb = _supabase()
        response = (
            sb.table("users")
            .select("recovery_a")
            .eq("username", username)
            .limit(1)
            .execute()
        )
        if not response.data or not response.data[0].get("recovery_a"):
            return False
        if response.data[0]["recovery_a"] != hash_pw(answer):
            return False
        now = datetime.utcnow().isoformat()
        update = (
            sb.table("users")
            .update({
                "password": hash_pw(new_password),
                "password_last_changed": now,
                "password_expired": 0
            })
            .eq("username", username)
            .execute()
        )
        return bool(update.data)
    conn = _conn()
    c = conn.cursor()

    c.execute("SELECT recovery_a FROM users WHERE username=?", (username,))
    row = c.fetchone()
    if not row or not row[0]:
        conn.close()
        return False

    if row[0] != hash_pw(answer):
        conn.close()
        return False

    now = datetime.utcnow().isoformat()
    c.execute("""
        UPDATE users
        SET password=?, password_last_changed=?, password_expired=0
        WHERE username=?
    """, (hash_pw(new_password), now, username))

    conn.commit()
    conn.close()
    return True
    


def add_history(username, expression, roots):
    if _use_supabase():
        sb = _supabase()
        sb.table("history").insert({
            "username": username,
            "expression": expression,
            "roots": roots
        }).execute()
        return
    conn = _conn(); c = conn.cursor()
    c.execute("INSERT INTO history(username,expression,roots) VALUES(?,?,?)", (username, expression, roots))
    conn.commit(); conn.close()

def get_history(username=None):
    if _use_supabase():
        sb = _supabase()
        query = sb.table("history").select("id,username,expression,roots,timestamp")
        if username:
            query = query.eq("username", username)
        response = query.order("timestamp", desc=True).execute()
        rows = response.data or []
        return [(r["id"], r["username"], r["expression"], r["roots"], r["timestamp"]) for r in rows]
    conn = _conn(); c = conn.cursor()
    if username:
        c.execute("SELECT id,username,expression,roots,timestamp FROM history WHERE username=? ORDER BY timestamp DESC", (username,))
    else:
        c.execute("SELECT id,username,expression,roots,timestamp FROM history ORDER BY timestamp DESC")
    rows = c.fetchall(); conn.close()
    return rows

def advanced_search_users(query, mode='fuzzy', fuzzy_threshold=75, limit=200, is_admin=None, case_sensitive=False):
    """
    mode: 'substring' | 'prefix' | 'tokens' | 'regex' | 'fuzzy'
    Always returns list of dicts: {username, phone, is_admin, role, created_at, ...}
    """
    if _use_supabase():
        collate_query = query if case_sensitive else query.lower()
        base_rows = _supabase_select(
            "users",
            "username,phone,is_admin,role,created_at",
            "username,phone,is_admin,created_at"
        ).data or []
        users = [{
            "username": r.get("username"),
            "phone": r.get("phone"),
            "is_admin": bool(r.get("is_admin")),
            "role": _role_from_row(r),
            "created_at": r.get("created_at")
        } for r in base_rows]
        if is_admin is not None:
            users = [u for u in users if u["is_admin"] == bool(is_admin)]

        if mode in ('substring', 'prefix', 'tokens'):
            if mode == 'substring':
                def match(u):
                    name = u["username"] or ""
                    phone = u["phone"] or ""
                    if case_sensitive:
                        return collate_query in name or collate_query in phone
                    return collate_query in name.lower() or collate_query in phone.lower()
            elif mode == 'prefix':
                def match(u):
                    name = u["username"] or ""
                    phone = u["phone"] or ""
                    if case_sensitive:
                        return name.startswith(collate_query) or phone.startswith(collate_query)
                    return name.lower().startswith(collate_query) or phone.lower().startswith(collate_query)
            else:
                tokens = [t for t in collate_query.split() if t]
                def match(u):
                    name = u["username"] or ""
                    phone = u["phone"] or ""
                    name_cmp = name if case_sensitive else name.lower()
                    phone_cmp = phone if case_sensitive else phone.lower()
                    return all(t in name_cmp or t in phone_cmp for t in tokens)
            filtered = [u for u in users if match(u)]
            return sorted(filtered, key=lambda x: x["username"] or "")[:limit]

        if mode == 'regex':
            flags = 0 if case_sensitive else re.I
            try:
                prog = re.compile(query, flags)
            except re.error:
                return []
            return [u for u in users if prog.search(u["username"] or "") or (u["phone"] and prog.search(u["phone"]))][:limit]

        if mode == 'fuzzy':
            try:
                from rapidfuzz import process, fuzz
            except Exception:
                return [u for u in users if collate_query in (u["username"] or "").lower() or (u["phone"] and collate_query in u["phone"])][:limit]
            choices = {u["username"]: u for u in users if u["username"]}
            matches = process.extract(query, choices.keys(), scorer=fuzz.WRatio, score_cutoff=fuzzy_threshold, limit=limit)
            results = []
            for m, score, _ in matches:
                u = choices[m]
                u_copy = u.copy()
                u_copy["score"] = score
                results.append(u_copy)
            if query.isdigit():
                for u in users:
                    if u["phone"] and query in u["phone"] and u not in results:
                        u_copy = u.copy()
                        u_copy["score"] = 100
                        results.append(u_copy)
            return results[:limit]
        return []

    conn = _conn()
    c = conn.cursor()
    try:
        # simple SQL-based searches include phone
        coll = '' if case_sensitive else ' COLLATE NOCASE'
        if mode in ('substring', 'prefix', 'tokens'):
            if mode == 'substring':
                pattern = f"%{query}%"
                sql = "SELECT username,phone,is_admin,role,created_at FROM users WHERE (username LIKE ? OR phone LIKE ?)" + coll + " ORDER BY username LIMIT ?"
                params = [pattern, pattern, limit]
                if is_admin is not None:
                    sql = sql.replace(" LIMIT ?", " AND is_admin=? LIMIT ?")
                    params = [pattern, pattern, 1 if is_admin else 0, limit]
            elif mode == 'prefix':
                pattern = f"{query}%"
                sql = "SELECT username,phone,is_admin,role,created_at FROM users WHERE (username LIKE ? OR phone LIKE ?)" + coll + " ORDER BY username LIMIT ?"
                params = [pattern, pattern, limit]
                if is_admin is not None:
                    sql = sql.replace(" LIMIT ?", " AND is_admin=? LIMIT ?")
                    params = [pattern, pattern, 1 if is_admin else 0, limit]
            else:  # tokens (AND all tokens in username or phone)
                tokens = [t for t in query.split() if t]
                clauses = " AND ".join(["(username LIKE ? OR phone LIKE ?)" + coll] * len(tokens))
                sql = f"SELECT username,phone,is_admin,role,created_at FROM users WHERE {clauses}"
                params = []
                for t in tokens:
                    params.extend([f"%{t}%", f"%{t}%"])
                if is_admin is not None:
                    sql += " AND is_admin=?"
                    params.append(1 if is_admin else 0)
                sql += " ORDER BY username LIMIT ?"
                params.append(limit)
            c.execute(sql, params)
            rows = c.fetchall()
            return [{
                "username": r[0],
                "phone": r[1],
                "is_admin": bool(r[2]),
                "role": (r[3] or "").strip().lower() or ("admin" if r[2] else "user"),
                "created_at": r[4]
            } for r in rows]

        # For regex/fuzzy: fetch all users then filter in Python so we can match username or phone consistently
        c.execute("SELECT username,phone,is_admin,role,created_at FROM users")
        all_rows = c.fetchall()
        users = [{
            "username": r[0],
            "phone": r[1],
            "is_admin": bool(r[2]),
            "role": (r[3] or "").strip().lower() or ("admin" if r[2] else "user"),
            "created_at": r[4]
        } for r in all_rows]
        if is_admin is not None:
            users = [u for u in users if u["is_admin"] == bool(is_admin)]

        if mode == 'regex':
            flags = 0 if case_sensitive else re.I
            try:
                prog = re.compile(query, flags)
            except re.error:
                return []
            return [u for u in users if prog.search(u["username"] or "") or (u["phone"] and prog.search(u["phone"]))][:limit]

        if mode == 'fuzzy':
            # fuzzy on username and phone (if available); fallback to substring if rapidfuzz missing
            try:
                from rapidfuzz import process, fuzz
            except Exception:
                return [u for u in users if query.lower() in (u["username"] or "").lower() or (u["phone"] and query in u["phone"])][:limit]
            # score usernames first
            choices = {u["username"]: u for u in users if u["username"]}
            matches = process.extract(query, choices.keys(), scorer=fuzz.WRatio, score_cutoff=fuzzy_threshold, limit=limit)
            results = []
            for m, score, _ in matches:
                u = choices[m]
                u_copy = u.copy()
                u_copy["score"] = score
                results.append(u_copy)
            # also match phone substrings for digit queries (avoid duplicates)
            if query.isdigit():
                for u in users:
                    if u["phone"] and query in u["phone"] and u not in results:
                        u_copy = u.copy()
                        u_copy["score"] = 100
                        results.append(u_copy)
            return results[:limit]
        return []
    finally:
        conn.close()
