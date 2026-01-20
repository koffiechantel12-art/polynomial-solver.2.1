import sqlite3, hashlib, os, re
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "data.db")
PASSWORD_EXPIRY_DAYS = 90

def _conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
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
        
    
    # ensure history table exists
    c.execute("""CREATE TABLE IF NOT EXISTS history(
        id INTEGER PRIMARY KEY, username TEXT, expression TEXT, roots TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()

    # ensure single admin account using environment variables (secure in deployment)
    admin_user = os.environ.get("ADMIN_USERNAME", "ad")
    admin_pw = os.environ.get("ADMIN_PASSWORD", "ad")
    c.execute("SELECT 1 FROM users WHERE username=?", (admin_user,))
    if not c.fetchone():
        h = hashlib.sha256(admin_pw.encode('utf-8')).hexdigest()
        now = datetime.utcnow().isoformat()
        c.execute(
            """
            INSERT INTO users(
                username, password, is_admin,
                created_at, password_last_changed, must_set_recovery
            )
            VALUES (?,?,?,?,?,0)
            """,
            (admin_user, h, 1, now, now)
        )
        conn.commit()

    conn.close()


def is_password_expired(password_last_changed):
    if not password_last_changed:
        return True
    last = datetime.fromisoformat(password_last_changed)
    return (datetime.utcnow() - last).days >= PASSWORD_EXPIRY_DAYS


def hash_pw(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def create_user(username, password, recovery_q=None, recovery_a=None, phone=None):
    conn = _conn()
    c = conn.cursor()
    try:
        if phone:
            c.execute("SELECT 1 FROM users WHERE phone=?", (phone,))
            if c.fetchone():
                return False

        now = datetime.utcnow().isoformat()

        c.execute("""
            INSERT INTO users(
                username, password,
                recovery_q, recovery_a,
                created_at, password_last_changed,
                must_set_recovery, phone
            )
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            username,
            hash_pw(password),
            recovery_q,
            hash_pw(recovery_a) if recovery_a else None,
            now,
            now,
            0,
            phone
        ))

        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()

def admin_create_user(username, password, phone=None):
    conn = _conn()
    c = conn.cursor()
    try:
        if phone:
            c.execute("SELECT 1 FROM users WHERE phone=?", (phone,))
            if c.fetchone():
                return False

        now = datetime.utcnow().isoformat()

        c.execute("""
            INSERT INTO users(
                username, password,
                created_at, password_last_changed,
                must_set_recovery, phone
            )
            VALUES (?,?,?,?,?,?)
        """, (
            username,
            hash_pw(password),
            now,
            now,
            1,
            phone
        ))

        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def verify_user(identifier, password):
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
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT username,is_admin,recovery_q,recovery_a,must_set_recovery,phone FROM users WHERE username=? OR phone=?", (identifier, identifier))
    row = c.fetchone(); conn.close()
    if not row:
        return None
    return {"username": row[0], "is_admin": bool(row[1]), "recovery_q": row[2], "recovery_a": row[3], "must_set_recovery": bool(row[4]), "phone": row[5]}

def list_users():
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT username,is_admin FROM users")
    users = [{"username": r[0], "is_admin": bool(r[1])} for r in c.fetchall()]
    conn.close()
    return users

def search_users(q):
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT username,is_admin FROM users WHERE username LIKE ? ORDER BY username LIMIT 200", (f"%{q}%",))
    users = [{"username": r[0], "is_admin": bool(r[1])} for r in c.fetchall()]
    conn.close()
    return users

def delete_user(username):
    # protect the admin 'ad' account
    if username == "ad":
        return False
    conn = _conn(); c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    changed = conn.total_changes
    conn.commit(); conn.close()
    return changed > 0

def set_recovery(username, question, answer):
    conn = _conn(); c = conn.cursor()
    c.execute("UPDATE users SET recovery_q=?, recovery_a=?, must_set_recovery=0 WHERE username=?", (question, hash_pw(answer), username))
    conn.commit(); ok = c.rowcount > 0
    conn.close()
    return ok

def recover_password(username, answer, new_password):
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
    conn = _conn(); c = conn.cursor()
    c.execute("INSERT INTO history(username,expression,roots) VALUES(?,?,?)", (username, expression, roots))
    conn.commit(); conn.close()

def get_history(username=None):
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
	Always returns list of dicts: {username, phone, is_admin, created_at, ...}
	"""
	conn = _conn(); c = conn.cursor()
	try:
		# simple SQL-based searches include phone
		coll = '' if case_sensitive else ' COLLATE NOCASE'
		if mode in ('substring', 'prefix', 'tokens'):
			if mode == 'substring':
				pattern = f"%{query}%"
				sql = "SELECT username,phone,is_admin,created_at FROM users WHERE (username LIKE ? OR phone LIKE ?)"+coll+" ORDER BY username LIMIT ?"
				params = [pattern, pattern, limit]
				if is_admin is not None:
					sql = sql.replace(" LIMIT ?", " AND is_admin=? LIMIT ?")
					params = [pattern, pattern, 1 if is_admin else 0, limit]
			elif mode == 'prefix':
				pattern = f"{query}%"
				sql = "SELECT username,phone,is_admin,created_at FROM users WHERE (username LIKE ? OR phone LIKE ?)"+coll+" ORDER BY username LIMIT ?"
				params = [pattern, pattern, limit]
				if is_admin is not None:
					sql = sql.replace(" LIMIT ?", " AND is_admin=? LIMIT ?")
					params = [pattern, pattern, 1 if is_admin else 0, limit]
			else:  # tokens (AND all tokens in username or phone)
				tokens = [t for t in query.split() if t]
				clauses = " AND ".join(["(username LIKE ? OR phone LIKE ?)"+coll] * len(tokens))
				sql = f"SELECT username,phone,is_admin,created_at FROM users WHERE {clauses}"
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
			return [{"username": r[0], "phone": r[1], "is_admin": bool(r[2]), "created_at": r[3]} for r in rows]

		# For regex/fuzzy: fetch all users then filter in Python so we can match username or phone consistently
		c.execute("SELECT username,phone,is_admin,created_at FROM users")
		all_rows = c.fetchall()
		users = [{"username": r[0], "phone": r[1], "is_admin": bool(r[2]), "created_at": r[3]} for r in all_rows]
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
				u_copy = u.copy(); u_copy["score"] = score
				results.append(u_copy)
			# also match phone substrings for digit queries (avoid duplicates)
			if query.isdigit():
				for u in users:
					if u["phone"] and query in u["phone"] and u not in results:
						u_copy = u.copy(); u_copy["score"] = 100
						results.append(u_copy)
			return results[:limit]
		return []
	finally:
		conn.close()
