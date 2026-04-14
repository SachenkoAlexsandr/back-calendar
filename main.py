import os
import asyncio
import sqlite3
import hashlib
import secrets
from datetime import datetime, date, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import httpx

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
DB_PATH = os.environ.get("DB_PATH", "planner.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "change_me_in_production_please")

# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token        TEXT PRIMARY KEY,
            user_id      INTEGER NOT NULL,
            created      TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            text         TEXT NOT NULL,
            tag          TEXT DEFAULT 'work',
            urgent       INTEGER DEFAULT 0,
            done         INTEGER DEFAULT 0,
            date         TEXT,
            week_from    TEXT,
            week_to      TEXT,
            created      TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            title        TEXT NOT NULL,
            start        TEXT NOT NULL,
            duration     INTEGER DEFAULT 30,
            color        TEXT DEFAULT 'blue',
            remind       INTEGER DEFAULT 15,
            date         TEXT NOT NULL,
            reminded     INTEGER DEFAULT 0,
            created      TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS event_templates (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            title        TEXT NOT NULL,
            start        TEXT NOT NULL,
            duration     INTEGER DEFAULT 30,
            color        TEXT DEFAULT 'blue',
            remind       INTEGER DEFAULT 15,
            rule         TEXT NOT NULL,
            weekdays     TEXT DEFAULT '',
            monthday     INTEGER DEFAULT 0,
            start_date   TEXT NOT NULL,
            end_date     TEXT DEFAULT '',
            created      TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS event_template_exceptions (
            template_id  INTEGER NOT NULL,
            date         TEXT NOT NULL,
            PRIMARY KEY (template_id, date),
            FOREIGN KEY(template_id) REFERENCES event_templates(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS event_template_reminded (
            template_id  INTEGER NOT NULL,
            date         TEXT NOT NULL,
            PRIMARY KEY (template_id, date),
            FOREIGN KEY(template_id) REFERENCES event_templates(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS streaks (
            user_id      INTEGER PRIMARY KEY,
            streak       INTEGER DEFAULT 0,
            last_date    TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()

# ── Helpers ───────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        SECRET_KEY.encode(),
        100_000
    ).hex()

def make_token() -> str:
    return secrets.token_urlsafe(32)

def get_user_from_token(token: str, conn):
    row = conn.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",
        (token,)
    ).fetchone()
    return row

def require_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Не авторизован")
    token = authorization[7:]
    conn = get_db()
    user = get_user_from_token(token, conn)
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Токен недействителен. Войди заново.")
    return dict(user)

# ── Recurrence helpers ────────────────────────────────────────────────────────

def _parse_iso(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()

def expand_template(tpl: dict, range_from: date, range_to: date) -> List[date]:
    """Возвращает список дат, когда шаблон срабатывает в диапазоне [range_from, range_to]."""
    rule = tpl["rule"]
    start = _parse_iso(tpl["start_date"])
    end = _parse_iso(tpl["end_date"]) if tpl.get("end_date") else None

    lo = max(range_from, start)
    hi = range_to if end is None else min(range_to, end)
    if lo > hi:
        return []

    dates: List[date] = []

    if rule == "weekly":
        wdays = {int(x) for x in (tpl.get("weekdays") or "").split(",") if x != ""}
        if not wdays:
            return []
        d = lo
        while d <= hi:
            if d.weekday() in wdays:
                dates.append(d)
            d += timedelta(days=1)

    elif rule == "biweekly":
        wdays = {int(x) for x in (tpl.get("weekdays") or "").split(",") if x != ""}
        if not wdays:
            return []
        # "Активные" недели — те, где (номер недели с начала старта) чётный
        start_monday = start - timedelta(days=start.weekday())
        d = lo
        while d <= hi:
            if d.weekday() in wdays:
                d_monday = d - timedelta(days=d.weekday())
                weeks_diff = (d_monday - start_monday).days // 7
                if weeks_diff >= 0 and weeks_diff % 2 == 0:
                    dates.append(d)
            d += timedelta(days=1)

    elif rule == "monthly":
        md = int(tpl.get("monthday") or 0)
        if md < 1 or md > 31:
            return []
        d = lo
        while d <= hi:
            if d.day == md:
                dates.append(d)
            d += timedelta(days=1)

    return dates

# ── Reminders ─────────────────────────────────────────────────────────────────

async def send_tg_message(chat_id: str, text: str):
    if not BOT_TOKEN:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            await client.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
            )
        except Exception as e:
            print(f"TG error: {e}")

async def reminder_loop():
    await asyncio.sleep(10)  # small startup delay
    while True:
        await asyncio.sleep(60)
        try:
            now = datetime.now()
            today_d = date.today()
            today = today_d.isoformat()
            conn = get_db()

            # 1) Обычные события
            rows = conn.execute("""
                SELECT e.*, u.username
                FROM events e
                JOIN users u ON u.id = e.user_id
                WHERE e.date = ? AND e.reminded = 0 AND e.remind > 0
            """, (today,)).fetchall()

            for row in rows:
                ev_time = datetime.strptime(f"{today} {row['start']}", "%Y-%m-%d %H:%M")
                remind_mins = row['remind']
                diff = (ev_time - now).total_seconds() / 60
                if remind_mins - 1 <= diff <= remind_mins + 1:
                    text = (
                        f"🔔 <b>Напоминание</b>\n\n"
                        f"Через {remind_mins} мин: <b>{row['title']}</b>\n"
                        f"Время: {row['start']}"
                    )
                    await send_tg_message(row['username'], text)
                    conn.execute("UPDATE events SET reminded=1 WHERE id=?", (row['id'],))

            # 2) Повторяющиеся события из шаблонов, которые срабатывают сегодня
            tpl_rows = conn.execute("""
                SELECT t.*, u.username
                FROM event_templates t
                JOIN users u ON u.id = t.user_id
                WHERE t.remind > 0
            """).fetchall()

            for tpl_row in tpl_rows:
                tpl = dict(tpl_row)
                occurs = expand_template(tpl, today_d, today_d)
                if not occurs:
                    continue
                # Пропуск если есть исключение
                exc = conn.execute(
                    "SELECT 1 FROM event_template_exceptions WHERE template_id=? AND date=?",
                    (tpl["id"], today)
                ).fetchone()
                if exc:
                    continue
                # Пропуск если уже напоминали сегодня
                rem = conn.execute(
                    "SELECT 1 FROM event_template_reminded WHERE template_id=? AND date=?",
                    (tpl["id"], today)
                ).fetchone()
                if rem:
                    continue

                ev_time = datetime.strptime(f"{today} {tpl['start']}", "%Y-%m-%d %H:%M")
                remind_mins = tpl['remind']
                diff = (ev_time - now).total_seconds() / 60
                if remind_mins - 1 <= diff <= remind_mins + 1:
                    text = (
                        f"🔔 <b>Напоминание</b>\n\n"
                        f"Через {remind_mins} мин: <b>{tpl['title']}</b>\n"
                        f"Время: {tpl['start']}"
                    )
                    await send_tg_message(tpl_row['username'], text)
                    conn.execute(
                        "INSERT OR IGNORE INTO event_template_reminded (template_id, date) VALUES (?,?)",
                        (tpl["id"], today)
                    )

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Reminder loop error: {e}")

# ── App ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    asyncio.create_task(reminder_loop())
    yield

app = FastAPI(lifespan=lifespan, title="Planner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth models ───────────────────────────────────────────────────────────────

class RegisterBody(BaseModel):
    username: str
    password: str
    display_name: str = ""

class LoginBody(BaseModel):
    username: str
    password: str

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.post("/auth/register")
def register(body: RegisterBody):
    if len(body.username) < 3:
        raise HTTPException(400, detail="Логин слишком короткий (мин. 3 символа)")
    if len(body.password) < 4:
        raise HTTPException(400, detail="Пароль слишком короткий (мин. 4 символа)")

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username=?", (body.username,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(400, detail="Такой пользователь уже существует")

    display = body.display_name or body.username
    pw_hash = hash_password(body.password)
    cur = conn.execute(
        "INSERT INTO users (username, display_name, password_hash) VALUES (?,?,?)",
        (body.username, display, pw_hash)
    )
    user_id = cur.lastrowid
    token = make_token()
    conn.execute("INSERT INTO sessions (token, user_id) VALUES (?,?)", (token, user_id))
    conn.commit()
    conn.close()

    return {"id": user_id, "username": body.username, "display_name": display, "token": token}

@app.post("/auth/login")
def login(body: LoginBody):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=?", (body.username,)
    ).fetchone()

    if not user or user["password_hash"] != hash_password(body.password):
        conn.close()
        raise HTTPException(401, detail="Неверный логин или пароль")

    token = make_token()
    conn.execute("INSERT INTO sessions (token, user_id) VALUES (?,?)", (token, user["id"]))
    conn.commit()
    conn.close()

    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "token": token
    }

@app.get("/auth/me")
def me(user=Depends(require_user)):
    return {"id": user["id"], "username": user["username"], "display_name": user["display_name"]}

@app.post("/auth/logout")
def do_logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
    return {"ok": True}

# ── Task models ───────────────────────────────────────────────────────────────

class TaskCreate(BaseModel):
    text: str
    tag: str = "work"
    urgent: bool = False
    date: str = ""
    week_from: str = ""
    week_to: str = ""

class TaskToggle(BaseModel):
    done: bool

# ── Task routes ───────────────────────────────────────────────────────────────

@app.get("/tasks")
def get_tasks(
    from_: str = Query("", alias="from"),
    to: str = "",
    user=Depends(require_user),
):
    conn = get_db()
    if from_ and to:
        rows = conn.execute(
            """SELECT * FROM tasks WHERE user_id=?
               AND (
                 (week_from >= ? AND week_to <= ?)
                 OR (date >= ? AND date <= ?)
               )
               ORDER BY urgent DESC, done ASC, id ASC""",
            (user["id"], from_, to, from_, to)
        ).fetchall()
    else:
        today = date.today().isoformat()
        rows = conn.execute(
            "SELECT * FROM tasks WHERE user_id=? AND date=? ORDER BY urgent DESC, done ASC, id ASC",
            (user["id"], today)
        ).fetchall()
    conn.close()
    return {"tasks": [dict(r) for r in rows]}

@app.post("/tasks")
def create_task(body: TaskCreate, user=Depends(require_user)):
    d = body.date or date.today().isoformat()
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO tasks (user_id, text, tag, urgent, date, week_from, week_to) VALUES (?,?,?,?,?,?,?)",
        (user["id"], body.text, body.tag, int(body.urgent), d, body.week_from, body.week_to)
    )
    task_id = cur.lastrowid
    conn.commit()
    task = dict(conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())
    conn.close()
    return task

@app.post("/tasks/{task_id}/toggle")
def toggle_task(task_id: int, body: TaskToggle, user=Depends(require_user)):
    conn = get_db()
    conn.execute(
        "UPDATE tasks SET done=? WHERE id=? AND user_id=?",
        (int(body.done), task_id, user["id"])
    )
    conn.commit()

    # Update streak
    today = date.today().isoformat()
    total = conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE user_id=? AND date=?", (user["id"], today)
    ).fetchone()[0]
    done_count = conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE user_id=? AND date=? AND done=1", (user["id"], today)
    ).fetchone()[0]

    if total > 0 and total == done_count:
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        row = conn.execute("SELECT * FROM streaks WHERE user_id=?", (user["id"],)).fetchone()
        if row:
            if row["last_date"] == yesterday:
                conn.execute("UPDATE streaks SET streak=streak+1, last_date=? WHERE user_id=?", (today, user["id"]))
            elif row["last_date"] != today:
                conn.execute("UPDATE streaks SET streak=1, last_date=? WHERE user_id=?", (today, user["id"]))
        else:
            conn.execute("INSERT INTO streaks (user_id, streak, last_date) VALUES (?,1,?)", (user["id"], today))
        conn.commit()

    conn.close()
    return {"ok": True}

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, user=Depends(require_user)):
    conn = get_db()
    conn.execute("DELETE FROM tasks WHERE id=? AND user_id=?", (task_id, user["id"]))
    conn.commit()
    conn.close()
    return {"ok": True}

# ── Event models ──────────────────────────────────────────────────────────────

class EventCreate(BaseModel):
    title: str
    start: str
    duration: int = 30
    color: str = "blue"
    remind: int = 15
    date: str = ""

# ── Event routes ──────────────────────────────────────────────────────────────

@app.get("/events")
def get_events(
    from_: str = Query("", alias="from"),
    to: str = "",
    user=Depends(require_user),
):
    conn = get_db()
    if from_ and to:
        range_from = _parse_iso(from_)
        range_to = _parse_iso(to)
        rows = conn.execute(
            "SELECT * FROM events WHERE user_id=? AND date>=? AND date<=? ORDER BY date ASC, start ASC",
            (user["id"], from_, to)
        ).fetchall()
    else:
        today = date.today().isoformat()
        range_from = range_to = date.today()
        rows = conn.execute(
            "SELECT * FROM events WHERE user_id=? AND date=? ORDER BY start ASC",
            (user["id"], today)
        ).fetchall()

    events_out = [dict(r) for r in rows]

    # Разворачиваем шаблоны
    tpl_rows = conn.execute(
        "SELECT * FROM event_templates WHERE user_id=?", (user["id"],)
    ).fetchall()
    for tpl_row in tpl_rows:
        tpl = dict(tpl_row)
        occur_dates = expand_template(tpl, range_from, range_to)
        if not occur_dates:
            continue
        # Собираем исключения одним запросом
        exc_rows = conn.execute(
            "SELECT date FROM event_template_exceptions WHERE template_id=?",
            (tpl["id"],)
        ).fetchall()
        exceptions = {r["date"] for r in exc_rows}
        for d in occur_dates:
            diso = d.isoformat()
            if diso in exceptions:
                continue
            events_out.append({
                "id": f"t{tpl['id']}_{diso}",
                "user_id": tpl["user_id"],
                "title": tpl["title"],
                "start": tpl["start"],
                "duration": tpl["duration"],
                "color": tpl["color"],
                "remind": tpl["remind"],
                "date": diso,
                "reminded": 0,
                "created": tpl["created"],
                "template_id": tpl["id"],
                "recurring": True,
                "rule": tpl["rule"],
            })

    conn.close()
    # Сортировка: по дате, потом по времени
    events_out.sort(key=lambda e: (e["date"], e["start"]))
    return {"events": events_out}

@app.post("/events")
def create_event(body: EventCreate, user=Depends(require_user)):
    d = body.date or date.today().isoformat()
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO events (user_id, title, start, duration, color, remind, date) VALUES (?,?,?,?,?,?,?)",
        (user["id"], body.title, body.start, body.duration, body.color, body.remind, d)
    )
    event_id = cur.lastrowid
    conn.commit()
    event = dict(conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone())
    conn.close()
    return event

@app.delete("/events/{event_id}")
def delete_event(event_id: int, user=Depends(require_user)):
    conn = get_db()
    conn.execute("DELETE FROM events WHERE id=? AND user_id=?", (event_id, user["id"]))
    conn.commit()
    conn.close()
    return {"ok": True}

# ── Event templates (recurring events) ────────────────────────────────────────

class EventTemplateCreate(BaseModel):
    title: str
    start: str
    duration: int = 30
    color: str = "blue"
    remind: int = 15
    rule: str                     # 'weekly' | 'biweekly' | 'monthly'
    weekdays: List[int] = []      # 0..6 (Mon..Sun)
    monthday: int = 0             # 1..31
    start_date: str = ""
    end_date: str = ""

def _validate_template(body: EventTemplateCreate):
    if body.rule not in ("weekly", "biweekly", "monthly"):
        raise HTTPException(400, detail="rule должен быть weekly/biweekly/monthly")
    if body.rule in ("weekly", "biweekly"):
        if not body.weekdays or any(d < 0 or d > 6 for d in body.weekdays):
            raise HTTPException(400, detail="Нужно выбрать хотя бы один день недели (0..6)")
    if body.rule == "monthly":
        if body.monthday < 1 or body.monthday > 31:
            raise HTTPException(400, detail="monthday должен быть 1..31")

@app.get("/event-templates")
def list_templates(user=Depends(require_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM event_templates WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["weekdays"] = [int(x) for x in (d.get("weekdays") or "").split(",") if x != ""]
        out.append(d)
    return {"templates": out}

@app.post("/event-templates")
def create_template(body: EventTemplateCreate, user=Depends(require_user)):
    _validate_template(body)
    sd = body.start_date or date.today().isoformat()
    weekdays_csv = ",".join(str(d) for d in sorted(set(body.weekdays)))
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO event_templates
           (user_id, title, start, duration, color, remind, rule, weekdays, monthday, start_date, end_date)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (user["id"], body.title, body.start, body.duration, body.color, body.remind,
         body.rule, weekdays_csv, body.monthday, sd, body.end_date)
    )
    tpl_id = cur.lastrowid
    conn.commit()
    row = dict(conn.execute("SELECT * FROM event_templates WHERE id=?", (tpl_id,)).fetchone())
    conn.close()
    row["weekdays"] = [int(x) for x in (row.get("weekdays") or "").split(",") if x != ""]
    return row

@app.delete("/event-templates/{tpl_id}")
def delete_template(tpl_id: int, user=Depends(require_user)):
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM event_templates WHERE id=? AND user_id=?",
        (tpl_id, user["id"])
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, detail="Шаблон не найден")
    conn.execute("DELETE FROM event_template_exceptions WHERE template_id=?", (tpl_id,))
    conn.execute("DELETE FROM event_template_reminded WHERE template_id=?", (tpl_id,))
    conn.execute("DELETE FROM event_templates WHERE id=?", (tpl_id,))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.delete("/event-templates/{tpl_id}/occurrence/{occ_date}")
def skip_occurrence(tpl_id: int, occ_date: str, user=Depends(require_user)):
    """Удалить один конкретный повтор (добавить в исключения). Шаблон продолжит действовать."""
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM event_templates WHERE id=? AND user_id=?",
        (tpl_id, user["id"])
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, detail="Шаблон не найден")
    # Проверим формат даты
    try:
        _parse_iso(occ_date)
    except ValueError:
        conn.close()
        raise HTTPException(400, detail="Неверный формат даты, нужно YYYY-MM-DD")
    conn.execute(
        "INSERT OR IGNORE INTO event_template_exceptions (template_id, date) VALUES (?,?)",
        (tpl_id, occ_date)
    )
    conn.commit()
    conn.close()
    return {"ok": True}

# ── Streak ────────────────────────────────────────────────────────────────────

@app.get("/streak")
def get_streak(user=Depends(require_user)):
    conn = get_db()
    row = conn.execute("SELECT streak FROM streaks WHERE user_id=?", (user["id"],)).fetchone()
    conn.close()
    return {"streak": row["streak"] if row else 0}

@app.get("/")
def root():
    return {"status": "ok", "version": "2.0"}
