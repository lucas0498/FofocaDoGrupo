from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
import sqlite3
import secrets
import time
import hashlib
import hmac
from pathlib import Path

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "gossipcrm.db"
STATIC_DIR = APP_DIR / "static"

app = FastAPI(title="GossipCRM", version="0.3")

# Serve frontend
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

security = HTTPBearer(auto_error=False)

STATUSES = ["LEAD", "APURACAO", "CONFIRMADO", "ARQUIVADO"]

# =========================
# Helpers: DB + Security
# =========================

PEPPER = "gossipcrm_pepper_v1"  # MVP. Em produção: usar env + bcrypt/argon2.

def hash_password(password: str) -> str:
    return hashlib.sha256((PEPPER + password).encode("utf-8")).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), stored_hash)

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def ensure_column(con: sqlite3.Connection, table: str, column: str, ddl: str):
    """Adds column if it does not exist. ddl example: 'ALTER TABLE users ADD COLUMN display_name TEXT' """
    cols = [r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        con.execute(ddl)

def init_db():
    con = db()
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Migration: add display_name if missing
    ensure_column(con, "users", "display_name", "ALTER TABLE users ADD COLUMN display_name TEXT")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS gossips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            details TEXT NOT NULL,
            source TEXT NOT NULL,
            credibility INTEGER NOT NULL,
            status TEXT NOT NULL,
            tags TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            created_by INTEGER NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            entity TEXT NOT NULL,
            entity_id INTEGER,
            meta TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Seed admin (backup)
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)",
            ("admin", hash_password("admin"), "Admin de Emergência")
        )
    else:
        # garante que admin tem display_name
        cur.execute("UPDATE users SET display_name = COALESCE(display_name, ?) WHERE username = ?", ("Admin de Emergência", "admin"))

    con.commit()
    con.close()

def log_action(user_id: int, action: str, entity: str, entity_id: Optional[int], meta: str):
    con = db()
    con.execute(
        "INSERT INTO audit_log (ts, user_id, action, entity, entity_id, meta) VALUES (?, ?, ?, ?, ?, ?)",
        (int(time.time()), user_id, action, entity, entity_id, meta),
    )
    con.commit()
    con.close()

def display_label(username: str, display_name: Optional[str]) -> str:
    dn = (display_name or "").strip()
    if dn and dn.lower() != username.lower():
        return f"{dn} (@{username})"
    return username

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sem token")

    token = creds.credentials
    con = db()
    row = con.execute("""
        SELECT u.id, u.username, u.display_name
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
    """, (token,)).fetchone()
    con.close()

    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"]
    }

# Init DB on startup/import
init_db()

# =========================
# Titles & Badges
# =========================

def title_for(count: int) -> str:
    if count >= 150: return "Lenda Urbana"
    if count >= 80:  return "Central de Boatos 24/7"
    if count >= 40:  return "Fofoqueiro(a) Sênior"
    if count >= 20:  return "Tia do Zap Premium"
    if count >= 10:  return "Vovózinha do Bairro"
    if count >= 3:   return "Ouvinte do Portão"
    return "Observador(a) Discreto(a)"

def badges_for(total: int, apuracao: int, confirmado: int, arquivado: int) -> List[str]:
    b = []
    if total >= 10: b.append("🥉 Bronze do Babado (10)")
    if total >= 50: b.append("🥈 Prata da Intriga (50)")
    if total >= 100: b.append("🥇 Ouro do Fuxico (100)")
    if apuracao >= 10: b.append("🕵️ Detetive de Bairro (10 apurações)")
    if confirmado >= 10: b.append("✅ Verificador(a) Oficial (10 confirmados)")
    if arquivado >= 20: b.append("🧹 Arquivista do Caos (20 arquivados)")
    return b

# =========================
# Models
# =========================

class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=40)
    username: str = Field(min_length=3, max_length=20)
    password: str = Field(min_length=4, max_length=50)

class LoginIn(BaseModel):
    username: str
    password: str

class LoginOut(BaseModel):
    token: str
    username: str
    display_name: Optional[str] = None

class GossipIn(BaseModel):
    title: str = Field(min_length=3, max_length=80)
    details: str = Field(min_length=3, max_length=1000)
    source: str = Field(min_length=1, max_length=80)
    credibility: int = Field(ge=0, le=100)
    status: str
    tags: List[str] = []

class GossipOut(BaseModel):
    id: int
    title: str
    details: str
    source: str
    credibility: int
    status: str
    tags: List[str]
    created_at: int
    updated_at: int
    created_by: str

class DashboardOut(BaseModel):
    total: int
    by_status: dict
    avg_credibility: float

# =========================
# Frontend Route
# =========================

@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))

# =========================
# Auth Endpoints
# =========================

@app.post("/api/register")
def register(data: RegisterIn):
    uname = data.username.strip().lower()
    dname = data.name.strip()

    if not uname.replace("_", "").isalnum():
        raise HTTPException(400, detail="Usuário deve ter letras/números e '_'")

    con = db()
    try:
        con.execute(
            "INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)",
            (uname, hash_password(data.password), dname),
        )
        con.commit()
    except sqlite3.IntegrityError:
        con.close()
        raise HTTPException(400, detail="Usuário já existe")
    con.close()
    return {"ok": True}

@app.post("/api/login", response_model=LoginOut)
def login(data: LoginIn):
    uname = data.username.strip().lower()
    con = db()
    row = con.execute(
        "SELECT id, username, password, display_name FROM users WHERE username = ?",
        (uname,),
    ).fetchone()

    if row is None or not verify_password(data.password, row["password"]):
        con.close()
        raise HTTPException(status_code=400, detail="Login inválido")

    token = secrets.token_urlsafe(32)
    con.execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, row["id"], int(time.time())),
    )
    con.commit()
    con.close()

    log_action(row["id"], "LOGIN", "session", None, "user logged in")
    return {"token": token, "username": row["username"], "display_name": row["display_name"]}

@app.post("/api/logout")
def logout(user=Depends(get_current_user), creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if creds is None:
        raise HTTPException(status_code=401, detail="Sem token")

    token = creds.credentials
    con = db()
    con.execute("DELETE FROM sessions WHERE token = ?", (token,))
    con.commit()
    con.close()

    log_action(user["id"], "LOGOUT", "session", None, "user logged out")
    return {"ok": True}

# =========================
# Core: Gossips
# =========================

def row_to_gossip_out(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "details": row["details"],
        "source": row["source"],
        "credibility": row["credibility"],
        "status": row["status"],
        "tags": [t for t in row["tags"].split(",") if t],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "created_by": row["created_by_label"],
    }

@app.get("/api/gossips", response_model=List[GossipOut])
def list_gossips(
    q: Optional[str] = None,
    status_filter: Optional[str] = None,
    user=Depends(get_current_user)
):
    con = db()
    sql = """
        SELECT
          g.*,
          u.username as u_username,
          u.display_name as u_display_name,
          (CASE
            WHEN u.display_name IS NOT NULL AND TRIM(u.display_name) <> '' AND LOWER(TRIM(u.display_name)) <> LOWER(u.username)
              THEN (u.display_name || ' (@' || u.username || ')')
            ELSE u.username
          END) as created_by_label
        FROM gossips g
        JOIN users u ON u.id = g.created_by
        WHERE 1=1
    """
    params = []
    if q:
        sql += " AND (g.title LIKE ? OR g.details LIKE ? OR g.source LIKE ? OR g.tags LIKE ?)"
        like = f"%{q}%"
        params += [like, like, like, like]
    if status_filter:
        sql += " AND g.status = ?"
        params.append(status_filter)

    sql += " ORDER BY g.updated_at DESC"
    rows = con.execute(sql, params).fetchall()
    con.close()
    return [row_to_gossip_out(r) for r in rows]

@app.post("/api/gossips", response_model=GossipOut)
def create_gossip(data: GossipIn, user=Depends(get_current_user)):
    if data.status not in STATUSES:
        raise HTTPException(400, detail="Status inválido")

    tags_csv = ",".join([t.strip() for t in data.tags if t.strip()])
    now = int(time.time())

    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO gossips (title, details, source, credibility, status, tags, created_at, updated_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (data.title, data.details, data.source, data.credibility, data.status, tags_csv, now, now, user["id"]))
    gid = cur.lastrowid
    con.commit()

    row = con.execute("""
        SELECT
          g.*,
          (CASE
            WHEN u.display_name IS NOT NULL AND TRIM(u.display_name) <> '' AND LOWER(TRIM(u.display_name)) <> LOWER(u.username)
              THEN (u.display_name || ' (@' || u.username || ')')
            ELSE u.username
          END) as created_by_label
        FROM gossips g
        JOIN users u ON u.id = g.created_by
        WHERE g.id = ?
    """, (gid,)).fetchone()
    con.close()

    log_action(user["id"], "CREATE", "gossip", gid, f"title={data.title}")
    return row_to_gossip_out(row)

@app.patch("/api/gossips/{gid}", response_model=GossipOut)
def update_gossip(gid: int, data: GossipIn, user=Depends(get_current_user)):
    if data.status not in STATUSES:
        raise HTTPException(400, detail="Status inválido")

    tags_csv = ",".join([t.strip() for t in data.tags if t.strip()])
    now = int(time.time())

    con = db()
    exists = con.execute("SELECT id FROM gossips WHERE id = ?", (gid,)).fetchone()
    if exists is None:
        con.close()
        raise HTTPException(404, detail="Não encontrado")

    con.execute("""
        UPDATE gossips
        SET title=?, details=?, source=?, credibility=?, status=?, tags=?, updated_at=?
        WHERE id=?
    """, (data.title, data.details, data.source, data.credibility, data.status, tags_csv, now, gid))
    con.commit()

    row = con.execute("""
        SELECT
          g.*,
          (CASE
            WHEN u.display_name IS NOT NULL AND TRIM(u.display_name) <> '' AND LOWER(TRIM(u.display_name)) <> LOWER(u.username)
              THEN (u.display_name || ' (@' || u.username || ')')
            ELSE u.username
          END) as created_by_label
        FROM gossips g
        JOIN users u ON u.id = g.created_by
        WHERE g.id = ?
    """, (gid,)).fetchone()
    con.close()

    log_action(user["id"], "UPDATE", "gossip", gid, f"status={data.status}")
    return row_to_gossip_out(row)

@app.delete("/api/gossips/{gid}")
def delete_gossip(gid: int, user=Depends(get_current_user)):
    con = db()
    exists = con.execute("SELECT id, title FROM gossips WHERE id = ?", (gid,)).fetchone()
    if exists is None:
        con.close()
        raise HTTPException(404, detail="Não encontrado")

    con.execute("DELETE FROM gossips WHERE id = ?", (gid,))
    con.commit()
    con.close()

    log_action(user["id"], "DELETE", "gossip", gid, f"title={exists['title']}")
    return {"ok": True}

# =========================
# Dashboard / Audit / Profile / Leaderboard
# =========================

@app.get("/api/dashboard", response_model=DashboardOut)
def dashboard(user=Depends(get_current_user)):
    con = db()
    total = con.execute("SELECT COUNT(*) c FROM gossips").fetchone()["c"]
    by_status = {}
    for s in STATUSES:
        by_status[s] = con.execute("SELECT COUNT(*) c FROM gossips WHERE status = ?", (s,)).fetchone()["c"]
    avg = con.execute("SELECT AVG(credibility) a FROM gossips").fetchone()["a"]
    con.close()
    return {"total": total, "by_status": by_status, "avg_credibility": float(avg or 0.0)}

@app.get("/api/audit")
def audit(limit: int = 50, user=Depends(get_current_user)):
    con = db()
    rows = con.execute("""
        SELECT a.ts, u.username, u.display_name, a.action, a.entity, a.entity_id, a.meta
        FROM audit_log a
        JOIN users u ON u.id = a.user_id
        ORDER BY a.ts DESC
        LIMIT ?
    """, (limit,)).fetchall()
    con.close()

    out = []
    for r in rows:
        out.append({
            "ts": r["ts"],
            "user": display_label(r["username"], r["display_name"]),
            "action": r["action"],
            "entity": r["entity"],
            "entity_id": r["entity_id"],
            "meta": r["meta"]
        })
    return out

@app.get("/api/me")
def me(user=Depends(get_current_user)):
    con = db()
    total = con.execute("SELECT COUNT(*) c FROM gossips WHERE created_by=?", (user["id"],)).fetchone()["c"]
    ap = con.execute("SELECT COUNT(*) c FROM gossips WHERE created_by=? AND status='APURACAO'", (user["id"],)).fetchone()["c"]
    cf = con.execute("SELECT COUNT(*) c FROM gossips WHERE created_by=? AND status='CONFIRMADO'", (user["id"],)).fetchone()["c"]
    ar = con.execute("SELECT COUNT(*) c FROM gossips WHERE created_by=? AND status='ARQUIVADO'", (user["id"],)).fetchone()["c"]

    # refresh display_name from DB (caso queira mudar depois)
    row = con.execute("SELECT username, display_name FROM users WHERE id=?", (user["id"],)).fetchone()
    con.close()

    return {
        "username": row["username"],
        "display_name": row["display_name"],
        "label": display_label(row["username"], row["display_name"]),
        "total_gossips": total,
        "title": title_for(total),
        "badges": badges_for(total, ap, cf, ar),
    }

@app.get("/api/leaderboard")
def leaderboard(limit: int = 10, user=Depends(get_current_user)):
    con = db()
    rows = con.execute("""
      SELECT u.username, u.display_name, COUNT(g.id) AS total
      FROM users u
      LEFT JOIN gossips g ON g.created_by = u.id
      GROUP BY u.id
      ORDER BY total DESC
      LIMIT ?
    """, (limit,)).fetchall()
    con.close()

    out = []
    for r in rows:
        out.append({"label": display_label(r["username"], r["display_name"]), "total": r["total"]})
    return out
