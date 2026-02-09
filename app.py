from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
import sqlite3
import secrets
import time
from pathlib import Path

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "gossipcrm.db"
STATIC_DIR = APP_DIR / "static"

app = FastAPI(title="GossipCRM", version="0.1")

# Serve frontend
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

security = HTTPBearer(auto_error=False)

STATUSES = ["LEAD", "APURACAO", "CONFIRMADO", "ARQUIVADO"]

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

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
    # Seed admin
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if cur.fetchone() is None:
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", "admin"))
    con.commit()
    con.close()

init_db()

def log_action(user_id: int, action: str, entity: str, entity_id: Optional[int], meta: str):
    con = db()
    con.execute(
        "INSERT INTO audit_log (ts, user_id, action, entity, entity_id, meta) VALUES (?, ?, ?, ?, ?, ?)",
        (int(time.time()), user_id, action, entity, entity_id, meta),
    )
    con.commit()
    con.close()

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sem token")
    token = creds.credentials
    con = db()
    row = con.execute("""
        SELECT u.id, u.username
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
    """, (token,)).fetchone()
    con.close()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    return {"id": row["id"], "username": row["username"]}

class LoginIn(BaseModel):
    username: str
    password: str

class LoginOut(BaseModel):
    token: str
    username: str

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

@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))

@app.post("/api/login", response_model=LoginOut)
def login(data: LoginIn):
    con = db()
    row = con.execute(
        "SELECT id, username FROM users WHERE username = ? AND password = ?",
        (data.username, data.password),
    ).fetchone()
    if row is None:
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
    return {"token": token, "username": row["username"]}

@app.post("/api/logout")
def logout(user=Depends(get_current_user), creds=Depends(security)):
    token = creds.credentials
    con = db()
    con.execute("DELETE FROM sessions WHERE token = ?", (token,))
    con.commit()
    con.close()
    log_action(user["id"], "LOGOUT", "session", None, "user logged out")
    return {"ok": True}

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
        "created_by": row["created_by_name"],
    }

@app.get("/api/gossips", response_model=List[GossipOut])
def list_gossips(q: Optional[str] = None, status_filter: Optional[str] = None, user=Depends(get_current_user)):
    con = db()
    sql = """
        SELECT g.*, u.username as created_by_name
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
        SELECT g.*, u.username as created_by_name
        FROM gossips g JOIN users u ON u.id = g.created_by
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
        SELECT g.*, u.username as created_by_name
        FROM gossips g JOIN users u ON u.id = g.created_by
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
        SELECT a.ts, u.username, a.action, a.entity, a.entity_id, a.meta
        FROM audit_log a JOIN users u ON u.id = a.user_id
        ORDER BY a.ts DESC
        LIMIT ?
    """, (limit,)).fetchall()
    con.close()
    return [{"ts": r["ts"], "user": r["username"], "action": r["action"], "entity": r["entity"], "entity_id": r["entity_id"], "meta": r["meta"]} for r in rows]
