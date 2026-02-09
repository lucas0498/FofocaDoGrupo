from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import sqlite3
import secrets
import time
import hashlib
import hmac
import re
from pathlib import Path

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "gossipcrm.db"
STATIC_DIR = APP_DIR / "static"

app = FastAPI(title="GossipCRM", version="0.6")

STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

security = HTTPBearer(auto_error=False)

STATUSES = ["LEAD", "APURACAO", "CONFIRMADO", "ARQUIVADO"]
REACTIONS = ["LIKE", "LOL", "WOW", "SUS", "FIRE"]  # 👍 😂 😮 🤔 🔥

# =========================
# Helpers: DB + Security
# =========================

PEPPER = "gossipcrm_pepper_v1"  # MVP. Em produção: env + bcrypt/argon2.

def hash_password(password: str) -> str:
    return hashlib.sha256((PEPPER + password).encode("utf-8")).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), stored_hash)

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def ensure_column(con: sqlite3.Connection, table: str, column: str, ddl: str):
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

    # Comments
    cur.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gossip_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(gossip_id) REFERENCES gossips(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Reactions (one reaction type per user per gossip)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gossip_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            reaction TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(gossip_id, user_id, reaction),
            FOREIGN KEY(gossip_id) REFERENCES gossips(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Notifications (mentions + comments on your gossip)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            to_user_id INTEGER NOT NULL,
            from_user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            entity TEXT NOT NULL,
            entity_id INTEGER,
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            read_at INTEGER,
            FOREIGN KEY(to_user_id) REFERENCES users(id),
            FOREIGN KEY(from_user_id) REFERENCES users(id)
        )
    """)

    # Seed admin (backup). Você pode remover depois se quiser.
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)",
            ("admin", hash_password("admin"), "Admin de Emergência")
        )
    else:
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

    return {"id": row["id"], "username": row["username"], "display_name": row["display_name"]}

def gossip_label_sql() -> str:
    return """
      (CASE
        WHEN u.display_name IS NOT NULL AND TRIM(u.display_name) <> '' AND LOWER(TRIM(u.display_name)) <> LOWER(u.username)
          THEN (u.display_name || ' (@' || u.username || ')')
        ELSE u.username
      END)
    """

def reaction_counts(con: sqlite3.Connection, gid: int) -> Dict[str, int]:
    rows = con.execute("""
        SELECT reaction, COUNT(*) AS c
        FROM reactions
        WHERE gossip_id = ?
        GROUP BY reaction
    """, (gid,)).fetchall()
    out = {r: 0 for r in REACTIONS}
    for r in rows:
        out[r["reaction"]] = int(r["c"])
    return out

def reaction_score(counts: Dict[str,int]) -> int:
    # dá pra ajustar o "algoritmo do babado"
    w = {"LIKE": 1, "LOL": 2, "WOW": 2, "SUS": 1, "FIRE": 3}
    return sum(counts.get(k,0)*w.get(k,1) for k in counts)

MENTION_RE = re.compile(r"@([a-zA-Z0-9_]{3,20})")

def extract_mentions(text: str) -> List[str]:
    return list({m.group(1).lower() for m in MENTION_RE.finditer(text or "")})

def create_notification(to_user_id: int, from_user_id: int, ntype: str, entity: str, entity_id: int, message: str):
    if to_user_id == from_user_id:
        return
    con = db()
    con.execute("""
      INSERT INTO notifications (to_user_id, from_user_id, type, entity, entity_id, message, created_at, read_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
    """, (to_user_id, from_user_id, ntype, entity, entity_id, message, int(time.time())))
    con.commit()
    con.close()

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
    details: str = Field(min_length=3, max_length=3000)
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
    created_by_id: int
    comment_count: int = 0
    reactions: Dict[str,int] = {}

class DashboardOut(BaseModel):
    total: int
    by_status: dict
    avg_credibility: float

class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=1200)

class CommentOut(BaseModel):
    id: int
    gossip_id: int
    body: str
    created_at: int
    author: str
    mentions: List[str] = []

class ToggleReactionIn(BaseModel):
    reaction: str

class NotificationOut(BaseModel):
    id: int
    type: str
    entity: str
    entity_id: Optional[int]
    message: str
    created_at: int
    read_at: Optional[int]

# =========================
# Front
# =========================

@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))

# =========================
# Auth
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
# Gossips / Feed / Backlog
# =========================

def row_to_gossip_out(con: sqlite3.Connection, row) -> Dict:
    counts = reaction_counts(con, row["id"])
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
        "created_by_id": row["created_by_id"],
        "comment_count": int(row["comment_count"] or 0),
        "reactions": counts,
    }

def base_gossip_select_sql(where: str) -> str:
    return f"""
        SELECT
          g.*,
          {gossip_label_sql()} as created_by_label,
          u.id as created_by_id,
          (SELECT COUNT(*) FROM comments c WHERE c.gossip_id = g.id) AS comment_count
        FROM gossips g
        JOIN users u ON u.id = g.created_by
        WHERE {where}
    """

@app.get("/api/feed", response_model=List[GossipOut])
def feed(
    q: Optional[str] = None,
    status_filter: Optional[str] = None,
    sort: str = "hot",   # hot | new | commented
    user=Depends(get_current_user)
):
    con = db()
    sql = base_gossip_select_sql("1=1")
    params = []

    if q:
        sql += " AND (g.title LIKE ? OR g.details LIKE ? OR g.source LIKE ? OR g.tags LIKE ?)"
        like = f"%{q}%"
        params += [like, like, like, like]
    if status_filter:
        sql += " AND g.status = ?"
        params.append(status_filter)

    if sort == "new":
        sql += " ORDER BY g.created_at DESC"
    elif sort == "commented":
        sql += " ORDER BY comment_count DESC, g.updated_at DESC"
    else:
        # hot: primeiro por comentários, depois por updated_at (front soma reações na UI)
        sql += " ORDER BY comment_count DESC, g.updated_at DESC"

    rows = con.execute(sql, params).fetchall()
    out = [row_to_gossip_out(con, r) for r in rows]
    con.close()
    return out

@app.get("/api/backlog", response_model=List[GossipOut])
def my_backlog(
    q: Optional[str] = None,
    status_filter: Optional[str] = None,
    user=Depends(get_current_user)
):
    con = db()
    sql = base_gossip_select_sql("g.created_by = ?")
    params = [user["id"]]

    if q:
        sql += " AND (g.title LIKE ? OR g.details LIKE ? OR g.source LIKE ? OR g.tags LIKE ?)"
        like = f"%{q}%"
        params += [like, like, like, like]
    if status_filter:
        sql += " AND g.status = ?"
        params.append(status_filter)

    sql += " ORDER BY g.updated_at DESC"
    rows = con.execute(sql, params).fetchall()
    out = [row_to_gossip_out(con, r) for r in rows]
    con.close()
    return out

@app.get("/api/gossips/{gid}", response_model=GossipOut)
def get_gossip(gid: int, user=Depends(get_current_user)):
    con = db()
    row = con.execute(base_gossip_select_sql("g.id = ?"), (gid,)).fetchone()
    if row is None:
        con.close()
        raise HTTPException(404, detail="Não encontrado")
    out = row_to_gossip_out(con, row)
    con.close()
    return out

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

    row = con.execute(base_gossip_select_sql("g.id = ?"), (gid,)).fetchone()
    out = row_to_gossip_out(con, row)
    con.close()

    log_action(user["id"], "CREATE", "gossip", gid, f"title={data.title}")
    return out

def require_owner(con: sqlite3.Connection, gid: int, user_id: int):
    row = con.execute("SELECT created_by FROM gossips WHERE id=?", (gid,)).fetchone()
    if row is None:
        raise HTTPException(404, detail="Não encontrado")
    if int(row["created_by"]) != int(user_id):
        raise HTTPException(403, detail="Só o autor pode alterar/excluir esta fofoca.")

@app.patch("/api/gossips/{gid}", response_model=GossipOut)
def update_gossip(gid: int, data: GossipIn, user=Depends(get_current_user)):
    if data.status not in STATUSES:
        raise HTTPException(400, detail="Status inválido")

    tags_csv = ",".join([t.strip() for t in data.tags if t.strip()])
    now = int(time.time())

    con = db()
    require_owner(con, gid, user["id"])

    con.execute("""
        UPDATE gossips
        SET title=?, details=?, source=?, credibility=?, status=?, tags=?, updated_at=?
        WHERE id=?
    """, (data.title, data.details, data.source, data.credibility, data.status, tags_csv, now, gid))
    con.commit()

    row = con.execute(base_gossip_select_sql("g.id = ?"), (gid,)).fetchone()
    out = row_to_gossip_out(con, row)
    con.close()

    log_action(user["id"], "UPDATE", "gossip", gid, f"status={data.status}")
    return out

@app.delete("/api/gossips/{gid}")
def delete_gossip(gid: int, user=Depends(get_current_user)):
    con = db()
    require_owner(con, gid, user["id"])

    con.execute("DELETE FROM gossips WHERE id = ?", (gid,))
    con.execute("DELETE FROM comments WHERE gossip_id = ?", (gid,))
    con.execute("DELETE FROM reactions WHERE gossip_id = ?", (gid,))
    con.commit()
    con.close()

    log_action(user["id"], "DELETE", "gossip", gid, f"deleted")
    return {"ok": True}

# =========================
# Comments + Mentions + Notifications
# =========================

@app.get("/api/gossips/{gid}/comments", response_model=List[CommentOut])
def list_comments(gid: int, user=Depends(get_current_user)):
    con = db()
    exists = con.execute("SELECT id FROM gossips WHERE id=?", (gid,)).fetchone()
    if exists is None:
        con.close()
        raise HTTPException(404, detail="Fofoca não encontrada")

    rows = con.execute(f"""
        SELECT
          c.id, c.gossip_id, c.body, c.created_at,
          {gossip_label_sql()} as author_label
        FROM comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.gossip_id = ?
        ORDER BY c.created_at ASC
    """, (gid,)).fetchall()
    con.close()

    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "gossip_id": r["gossip_id"],
            "body": r["body"],
            "created_at": r["created_at"],
            "author": r["author_label"],
            "mentions": extract_mentions(r["body"]),
        })
    return out

@app.post("/api/gossips/{gid}/comments", response_model=CommentOut)
def create_comment(gid: int, data: CommentIn, user=Depends(get_current_user)):
    body = (data.body or "").strip()
    if not body:
        raise HTTPException(400, detail="Comentário vazio")

    con = db()
    g = con.execute("SELECT id, created_by, title FROM gossips WHERE id=?", (gid,)).fetchone()
    if g is None:
        con.close()
        raise HTTPException(404, detail="Fofoca não encontrada")

    now = int(time.time())
    cur = con.cursor()
    cur.execute(
        "INSERT INTO comments (gossip_id, user_id, body, created_at) VALUES (?, ?, ?, ?)",
        (gid, user["id"], body, now),
    )
    cid = cur.lastrowid

    # bump updated_at to keep “hot”
    con.execute("UPDATE gossips SET updated_at=? WHERE id=?", (now, gid))
    con.commit()

    # Notify author: someone commented your gossip
    author_id = int(g["created_by"])
    if author_id != user["id"]:
        create_notification(
            to_user_id=author_id,
            from_user_id=user["id"],
            ntype="COMMENT",
            entity="gossip",
            entity_id=gid,
            message=f"Comentaram na sua fofoca: “{g['title']}”"
        )

    # Mentions: @username
    mentions = extract_mentions(body)
    if mentions:
        rows = con.execute(
            f"SELECT id, username FROM users WHERE username IN ({','.join(['?']*len(mentions))})",
            mentions
        ).fetchall()
        for r in rows:
            create_notification(
                to_user_id=int(r["id"]),
                from_user_id=user["id"],
                ntype="MENTION",
                entity="gossip",
                entity_id=gid,
                message=f"Você foi mencionado(a) em um comentário: @{r['username']}"
            )

    # Build response
    row = con.execute(f"""
        SELECT
          c.id, c.gossip_id, c.body, c.created_at,
          {gossip_label_sql()} as author_label
        FROM comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.id = ?
    """, (cid,)).fetchone()
    con.close()

    log_action(user["id"], "COMMENT", "gossip", gid, f"comment_id={cid}")
    return {
        "id": row["id"],
        "gossip_id": row["gossip_id"],
        "body": row["body"],
        "created_at": row["created_at"],
        "author": row["author_label"],
        "mentions": extract_mentions(row["body"]),
    }

# =========================
# Reactions
# =========================

@app.post("/api/gossips/{gid}/reactions/toggle")
def toggle_reaction(gid: int, data: ToggleReactionIn, user=Depends(get_current_user)):
    reaction = (data.reaction or "").strip().upper()
    if reaction not in REACTIONS:
        raise HTTPException(400, detail="Reação inválida")

    con = db()
    exists = con.execute("SELECT id FROM gossips WHERE id=?", (gid,)).fetchone()
    if exists is None:
        con.close()
        raise HTTPException(404, detail="Fofoca não encontrada")

    now = int(time.time())
    row = con.execute("""
        SELECT id FROM reactions
        WHERE gossip_id=? AND user_id=? AND reaction=?
    """, (gid, user["id"], reaction)).fetchone()

    if row is None:
        con.execute("""
          INSERT OR IGNORE INTO reactions (gossip_id, user_id, reaction, created_at)
          VALUES (?, ?, ?, ?)
        """, (gid, user["id"], reaction, now))
        action = "ADD"
    else:
        con.execute("DELETE FROM reactions WHERE id=?", (row["id"],))
        action = "REMOVE"

    # bump updated_at to keep “hot”
    con.execute("UPDATE gossips SET updated_at=? WHERE id=?", (now, gid))
    con.commit()

    counts = reaction_counts(con, gid)
    con.close()

    log_action(user["id"], f"REACTION_{action}", "gossip", gid, f"{reaction}")
    return {"ok": True, "reactions": counts}

# =========================
# Notifications
# =========================

@app.get("/api/notifications", response_model=List[NotificationOut])
def list_notifications(limit: int = 30, only_unread: int = 0, user=Depends(get_current_user)):
    con = db()
    if only_unread:
        rows = con.execute("""
          SELECT id, type, entity, entity_id, message, created_at, read_at
          FROM notifications
          WHERE to_user_id=? AND read_at IS NULL
          ORDER BY created_at DESC
          LIMIT ?
        """, (user["id"], limit)).fetchall()
    else:
        rows = con.execute("""
          SELECT id, type, entity, entity_id, message, created_at, read_at
          FROM notifications
          WHERE to_user_id=?
          ORDER BY created_at DESC
          LIMIT ?
        """, (user["id"], limit)).fetchall()
    con.close()

    return [{
        "id": r["id"],
        "type": r["type"],
        "entity": r["entity"],
        "entity_id": r["entity_id"],
        "message": r["message"],
        "created_at": r["created_at"],
        "read_at": r["read_at"],
    } for r in rows]

@app.post("/api/notifications/{nid}/read")
def mark_read(nid: int, user=Depends(get_current_user)):
    con = db()
    row = con.execute("SELECT id FROM notifications WHERE id=? AND to_user_id=?", (nid, user["id"])).fetchone()
    if row is None:
        con.close()
        raise HTTPException(404, detail="Notificação não encontrada")
    con.execute("UPDATE notifications SET read_at=? WHERE id=?", (int(time.time()), nid))
    con.commit()
    con.close()
    return {"ok": True}

@app.get("/api/notifications/unread_count")
def unread_count(user=Depends(get_current_user)):
    con = db()
    c = con.execute("SELECT COUNT(*) AS c FROM notifications WHERE to_user_id=? AND read_at IS NULL", (user["id"],)).fetchone()["c"]
    con.close()
    return {"count": int(c)}

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
def audit(limit: int = 30, user=Depends(get_current_user)):
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
