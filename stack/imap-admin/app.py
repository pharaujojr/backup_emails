import os
import re
import shlex
import sqlite3
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from typing import Optional

import docker
from docker.errors import APIError, NotFound
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, Response, flash, g, redirect, render_template, request, session, url_for
from passlib.hash import sha512_crypt
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE = Path(os.environ.get("IMAP_ADMIN_DB", "/data/imap_admin.db"))
RUN_TIMEOUT = int(os.environ.get("IMAP_ADMIN_RUN_TIMEOUT", "7200"))
MASTER_KEY = os.environ.get("MASTER_KEY", "")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
ROUND_CUBE_TEST_URL = os.environ.get("ROUNDCUBE_TEST_URL", "http://<NAS_IP>:8080")
ROUND_CUBE_PROD_URL = os.environ.get("ROUNDCUBE_PROD_URL", "https://webmail.example.com")

DOVECOT_USERS_FILE = Path(os.environ.get("DOVECOT_USERS_FILE", "/data/dovecot-users/users"))
USERS_FILE_MODE = int(os.environ.get("DOVECOT_USERS_FILE_MODE", "644"), 8)
MAIL_ROOT = Path(os.environ.get("MAIL_ROOT", "/data/mail"))
IMAPSYNC_LOG_ROOT = Path(os.environ.get("IMAPSYNC_LOG_ROOT", "/data/imapsync-logs"))
IMAPSYNC_CONTAINER = os.environ.get("IMAPSYNC_CONTAINER", "mailarchive_imapsync")
DOVECOT_IMAP_HOST = os.environ.get("DOVECOT_IMAP_HOST", "mailarchive_dovecot")
DOVECOT_IMAP_PORT = int(os.environ.get("DOVECOT_IMAP_PORT", "31143"))
MAIL_UID = int(os.environ.get("MAIL_UID", "1000"))
MAIL_GID = int(os.environ.get("MAIL_GID", "1000"))

FORBIDDEN_OPTION_ROOTS = {
    "delete",
    "delete1",
    "delete2",
    "expunge",
    "expunge1",
    "expunge2",
    "deletefolders",
    "delete2folders",
}
FORBIDDEN_EXACT = {"fast"}

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY or os.urandom(32)


def _duration_fmt(started: Optional[str], finished: Optional[str]) -> str:
    """Return human-readable duration like '2m 34s'."""
    if not started or not finished:
        return "—"
    try:
        fmt = "%Y-%m-%dT%H:%M:%S"
        s = datetime.strptime(started[:19], fmt)
        f = datetime.strptime(finished[:19], fmt)
        secs = max(0, int((f - s).total_seconds()))
        if secs < 60:
            return f"{secs}s"
        m, s = divmod(secs, 60)
        return f"{m}m {s}s"
    except (ValueError, TypeError):
        return "—"


app.jinja_env.globals["duration_fmt"] = _duration_fmt


BRT = timezone(timedelta(hours=-4))  # America/Cuiaba (UTC-4)


def _fmt_brt(iso_str: Optional[str]) -> Optional[str]:
    """Convert UTC ISO string to Brazilian Portuguese date/time in BRT (UTC-4)."""
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_brt = dt.astimezone(BRT)
        return dt_brt.strftime("%d/%m/%Y %H:%M")
    except (ValueError, TypeError):
        # fallback: just crop the raw string
        return iso_str[:16].replace("T", " ")

db_lock = threading.Lock()
users_file_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=4)
running_sources = set()
running_sources_lock = threading.Lock()

scheduler = BackgroundScheduler(
    jobstores={"default": SQLAlchemyJobStore(url=f"sqlite:///{DATABASE}")},
    job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 86400},
    timezone="UTC",
)
scheduler_started = False


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_connect():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    if "db" not in g:
        g.db = db_connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with db_lock:
        conn = db_connect()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS local_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_encrypted TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_password_reset_at TEXT
            );

            CREATE TABLE IF NOT EXISTS source_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                local_account_id INTEGER NOT NULL,
                source_name TEXT NOT NULL,
                host1 TEXT NOT NULL,
                port1 INTEGER NOT NULL DEFAULT 993,
                security1 TEXT NOT NULL DEFAULT 'ssl',
                user1 TEXT NOT NULL,
                password1_encrypted TEXT NOT NULL,
                include_folders TEXT NOT NULL DEFAULT '',
                exclude_folders TEXT NOT NULL DEFAULT '',
                extra_args TEXT NOT NULL DEFAULT '',
                schedule_enabled INTEGER NOT NULL DEFAULT 0,
                schedule_mode TEXT NOT NULL DEFAULT 'interval',
                schedule_value TEXT NOT NULL DEFAULT '360',
                last_sync_at TEXT,
                FOREIGN KEY(local_account_id) REFERENCES local_accounts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS source_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER NOT NULL,
                local_account_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                trigger_type TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_seconds INTEGER,
                exit_code INTEGER,
                log_path TEXT NOT NULL,
                log_size_bytes INTEGER,
                error_message TEXT,
                command_redacted TEXT NOT NULL,
                FOREIGN KEY(source_id) REFERENCES source_accounts(id) ON DELETE CASCADE,
                FOREIGN KEY(local_account_id) REFERENCES local_accounts(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_source_runs_source_id ON source_runs(source_id);
            CREATE INDEX IF NOT EXISTS idx_source_runs_started_at ON source_runs(started_at);
            """
        )
        ensure_text_columns(conn)
        conn.commit()
        conn.close()


def ensure_text_columns(conn):
    migrations = [
        ("local_accounts", "password_hash"),
        ("local_accounts", "password_encrypted"),
        ("source_accounts", "password1_encrypted"),
    ]
    for table_name, column_name in migrations:
        row = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        col = next((c for c in row if c["name"] == column_name), None)
        if col is None:
            continue
        col_type = (col["type"] or "").upper()
        if "TEXT" in col_type:
            continue
        if table_name == "local_accounts":
            conn.executescript(
                """
                ALTER TABLE local_accounts RENAME TO local_accounts_old;
                CREATE TABLE local_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    password_encrypted TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_password_reset_at TEXT
                );
                INSERT INTO local_accounts
                (id, email, password_hash, password_encrypted, enabled, created_at, updated_at, last_password_reset_at)
                SELECT id, email, password_hash, password_encrypted, enabled, created_at, updated_at, last_password_reset_at
                FROM local_accounts_old;
                DROP TABLE local_accounts_old;
                """
            )
        if table_name == "source_accounts":
            conn.executescript(
                """
                ALTER TABLE source_accounts RENAME TO source_accounts_old;
                CREATE TABLE source_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    local_account_id INTEGER NOT NULL,
                    source_name TEXT NOT NULL,
                    host1 TEXT NOT NULL,
                    port1 INTEGER NOT NULL DEFAULT 993,
                    security1 TEXT NOT NULL DEFAULT 'ssl',
                    user1 TEXT NOT NULL,
                    password1_encrypted TEXT NOT NULL,
                    include_folders TEXT NOT NULL DEFAULT '',
                    exclude_folders TEXT NOT NULL DEFAULT '',
                    extra_args TEXT NOT NULL DEFAULT '',
                    schedule_enabled INTEGER NOT NULL DEFAULT 0,
                    schedule_mode TEXT NOT NULL DEFAULT 'interval',
                    schedule_value TEXT NOT NULL DEFAULT '360',
                    last_sync_at TEXT,
                    FOREIGN KEY(local_account_id) REFERENCES local_accounts(id) ON DELETE CASCADE
                );
                INSERT INTO source_accounts
                (id, local_account_id, source_name, host1, port1, security1, user1, password1_encrypted,
                 include_folders, exclude_folders, extra_args, schedule_enabled, schedule_mode, schedule_value, last_sync_at)
                SELECT id, local_account_id, source_name, host1, port1, security1, user1, password1_encrypted,
                       include_folders, exclude_folders, extra_args, schedule_enabled, schedule_mode, schedule_value, last_sync_at
                FROM source_accounts_old;
                DROP TABLE source_accounts_old;
                """
            )


def ensure_admin():
    if not ADMIN_PASSWORD:
        raise RuntimeError("ADMIN_PASSWORD env var is required")
    conn = db_connect()
    row = conn.execute("SELECT id FROM admins LIMIT 1").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (ADMIN_USER, generate_password_hash(ADMIN_PASSWORD), utcnow_iso()),
        )
        conn.commit()
    conn.close()


def get_fernet():
    if not MASTER_KEY:
        raise RuntimeError("MASTER_KEY env var is required")
    try:
        return Fernet(MASTER_KEY.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("MASTER_KEY must be a valid Fernet key") from exc


def encrypt_secret(value):
    if value is None:
        return ""
    return get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value):
    try:
        return get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as exc:
        raise RuntimeError("Unable to decrypt stored secret. Check MASTER_KEY.") from exc


def generate_password():
    # Avoid symbols that are commonly misread when manually typing.
    return Fernet.generate_key().decode("utf-8").replace("-", "A").replace("_", "b")[:24]


def validate_local_password(password):
    if password != (password or "").strip():
        raise ValueError("A senha da conta local não pode iniciar/terminar com espaços")
    if "\n" in password or "\r" in password:
        raise ValueError("A senha da conta local não pode conter quebra de linha")
    if len(password or "") < 12:
        raise ValueError("A senha da conta local deve ter no mínimo 12 caracteres")


def validate_sha512_crypt_hash(password_hash):
    if not password_hash.startswith("$6$"):
        raise ValueError("Hash inválido: hash SHA512-CRYPT deve iniciar com $6$")
    if len(password_hash) < 90:
        raise ValueError("Hash inválido: hash SHA512-CRYPT muito curto")


def generate_sha512_crypt_hash(password):
    # Prefer generating hash using Dovecot itself to avoid any cross-implementation edge case.
    try:
        client = docker.from_env()
        container = get_running_container(client, DOVECOT_IMAP_HOST, wait_timeout=25)
        code, out = exec_text(
            container,
            ["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password],
        )
        if code == 0 and out:
            hashed = out.strip()
            prefix = "{SHA512-CRYPT}"
            if hashed.startswith(prefix):
                hashed = hashed[len(prefix) :]
            validate_sha512_crypt_hash(hashed)
            return hashed
    except Exception:
        pass

    hashed = sha512_crypt.hash(password)
    validate_sha512_crypt_hash(hashed)
    return hashed


def normalize_option(token):
    return token.strip().lower().lstrip("-")


def is_forbidden_option(token):
    normalized = normalize_option(token)
    if not normalized:
        return False
    if normalized in FORBIDDEN_EXACT:
        return True
    for root in FORBIDDEN_OPTION_ROOTS:
        if normalized.startswith(root):
            return True
    return False


def validate_extra_args(extra_args):
    tokens = shlex.split(extra_args or "")
    for token in tokens:
        if is_forbidden_option(token):
            raise ValueError(f"Forbidden imapsync option detected: {token}")
    return tokens


def parse_folder_lines(raw):
    if not raw:
        return []
    chunks = []
    for line in raw.replace(",", "\n").splitlines():
        item = line.strip()
        if item:
            chunks.append(item)
    return chunks


def redact_text(text, secrets):
    sanitized = text
    for secret in secrets:
        if secret:
            sanitized = sanitized.replace(secret, "***")
    return sanitized


def redact_command_parts(parts, password1, password2):
    redacted = list(parts)
    for idx, value in enumerate(redacted):
        if value in {"--password1", "--password2"} and idx + 1 < len(redacted):
            redacted[idx + 1] = "***"
    rendered = " ".join(shlex.quote(p) for p in redacted)
    return redact_text(rendered, [password1, password2])


def exec_text(container, cmd):
    retries = 8
    wait_seconds = 2
    for attempt in range(1, retries + 1):
        try:
            result = container.exec_run(cmd=cmd)
            output = (result.output or b"").decode("utf-8", errors="replace").strip()
            return result.exit_code, output
        except APIError as exc:
            msg = str(exc)
            if "is restarting" in msg.lower() and attempt < retries:
                time.sleep(wait_seconds)
                try:
                    container.reload()
                except Exception:
                    pass
                continue
            raise


def get_running_container(client, name, wait_timeout=30):
    deadline = time.time() + wait_timeout
    container = client.containers.get(name)
    while True:
        try:
            container.reload()
        except Exception:
            pass
        status = getattr(container, "status", "") or ""
        if status == "running":
            return container
        if status == "restarting" and time.time() < deadline:
            time.sleep(2)
            continue
        tail = ""
        try:
            tail = (container.logs(tail=20) or b"").decode("utf-8", errors="replace")
        except Exception:
            tail = ""
        details = f"Container {name} não está running (status={status})."
        if tail:
            details = f"{details} Últimas linhas do container: {tail[-280:]}"
        raise RuntimeError(details)


def validate_email(email):
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValueError("Email inválido")


def maildir_size_fmt(email: str) -> str:  # noqa: E501
    """Return human-readable total size of the user's mail directory."""
    user_root = MAIL_ROOT / email
    if not user_root.exists():
        return "0 B"
    try:
        total = sum(f.stat().st_size for f in user_root.rglob("*") if f.is_file())
    except OSError:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if total < 1024:
            return f"{total:.1f} {unit}" if unit != "B" else f"{total} {unit}"
        total /= 1024
    return f"{total:.1f} PB"


def ensure_maildir(email):
    user_root = MAIL_ROOT / email
    maildir = user_root / "Maildir"
    for path in (maildir, maildir / "cur", maildir / "new", maildir / "tmp"):
        path.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(user_root):
        os.chown(root, MAIL_UID, MAIL_GID)
        for dirname in dirs:
            os.chown(Path(root) / dirname, MAIL_UID, MAIL_GID)
        for filename in files:
            os.chown(Path(root) / filename, MAIL_UID, MAIL_GID)


def rebuild_dovecot_users_file(conn):
    DOVECOT_USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock_path = DOVECOT_USERS_FILE.with_suffix(".lock")
    managed_accounts = conn.execute(
        "SELECT email, password_hash, enabled FROM local_accounts ORDER BY email"
    ).fetchall()
    for row in managed_accounts:
        if row["enabled"]:
            validate_sha512_crypt_hash(row["password_hash"])
    managed_emails = {row["email"] for row in managed_accounts}

    with users_file_lock:
        with open(lock_path, "w", encoding="utf-8") as lock_file:
            import fcntl

            fcntl.flock(lock_file, fcntl.LOCK_EX)
            existing_lines = []
            if DOVECOT_USERS_FILE.exists():
                existing_lines = DOVECOT_USERS_FILE.read_text(encoding="utf-8").splitlines()

            kept = []
            seen_users = set()
            for line in existing_lines:
                stripped = line.strip()
                if not stripped:
                    kept.append(line)
                    continue
                if stripped.startswith("# managed-by-imap-admin"):
                    continue
                if stripped.startswith("# managed-disabled:"):
                    continue
                if stripped.startswith("#"):
                    kept.append(line)
                    continue
                if ":" not in stripped:
                    kept.append(line)
                    continue
                user = stripped.split(":", 1)[0].strip()
                # Drop legacy wildcard entries that can hijack auth with user=%u.
                if user in {"*", "*@*"} or stripped.startswith("*:") or "user=%u" in stripped:
                    continue
                if user in managed_emails:
                    continue
                if user in seen_users:
                    continue
                seen_users.add(user)
                kept.append(line)

            output = kept[:]
            if output and output[-1].strip():
                output.append("")
            output.append("# managed-by-imap-admin")
            for row in managed_accounts:
                if row["enabled"]:
                    line = f'{row["email"]}:{{SHA512-CRYPT}}{row["password_hash"]}'
                    if "\n" in line or "\r" in line:
                        raise ValueError("Linha inválida no passwd-file (quebra detectada)")
                    output.append(line)
                else:
                    output.append(f'# managed-disabled: {row["email"]}')

            content = "\n".join(output).rstrip() + "\n"
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                dir=str(DOVECOT_USERS_FILE.parent),
                prefix="users.",
                suffix=".tmp",
            ) as temp_file:
                temp_file.write(content)
                temp_path = Path(temp_file.name)
            os.chmod(temp_path, USERS_FILE_MODE)
            os.replace(temp_path, DOVECOT_USERS_FILE)
            os.chmod(DOVECOT_USERS_FILE, USERS_FILE_MODE)
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def verify_dovecot_auth(email, password):
    client = docker.from_env()
    container = get_running_container(client, DOVECOT_IMAP_HOST, wait_timeout=45)
    auth_code, output = exec_text(container, ["doveadm", "auth", "test", email, password])
    if auth_code != 0:
        raise RuntimeError(
            f"Dovecot não confirmou a senha recém-definida para {email}. "
            f"Saída: {output[:220]}"
        )


def sync_dovecot_users_file_or_rollback(conn, email=None, password=None):
    try:
        rebuild_dovecot_users_file(conn)
        if email is not None and password is not None:
            verify_dovecot_auth(email, password)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def scheduler_job_id(source_id):
    return f"source-sync-{source_id}"


def sync_scheduler_for_source(source_id):
    conn = db_connect()
    source = conn.execute("SELECT * FROM source_accounts WHERE id = ?", (source_id,)).fetchone()
    conn.close()
    job_id = scheduler_job_id(source_id)
    existing = scheduler.get_job(job_id)

    if source is None or not source["schedule_enabled"]:
        if existing:
            scheduler.remove_job(job_id)
        return

    mode = source["schedule_mode"]
    value = (source["schedule_value"] or "").strip()
    trigger = None
    if mode == "cron":
        trigger = CronTrigger.from_crontab(value)
    else:
        minutes = int(value or "360")
        if minutes < 1:
            minutes = 1
        from apscheduler.triggers.interval import IntervalTrigger

        trigger = IntervalTrigger(minutes=minutes)

    if existing:
        scheduler.reschedule_job(job_id, trigger=trigger)
    else:
        scheduler.add_job(
            func=scheduled_import_runner,
            trigger=trigger,
            args=[source_id],
            id=job_id,
            replace_existing=True,
        )


def start_scheduler_once():
    global scheduler_started
    if scheduler_started:
        return
    scheduler.start()
    scheduler_started = True
    conn = db_connect()
    source_ids = conn.execute("SELECT id FROM source_accounts").fetchall()
    conn.close()
    for row in source_ids:
        try:
            sync_scheduler_for_source(row["id"])
        except Exception:
            continue


def schedule_import_async(source_id, trigger_type):
    with running_sources_lock:
        if source_id in running_sources:
            return False
        running_sources.add(source_id)
    executor.submit(run_imapsync_job, source_id, trigger_type)
    return True


def scheduled_import_runner(source_id):
    schedule_import_async(source_id, "scheduler")


def run_imapsync_job(source_id, trigger_type):
    start_ts = time.time()
    conn = db_connect()
    run_id = None
    log_file_path = ""
    try:
        source = conn.execute("SELECT * FROM source_accounts WHERE id = ?", (source_id,)).fetchone()
        if source is None:
            return
        account = conn.execute(
            "SELECT * FROM local_accounts WHERE id = ?", (source["local_account_id"],)
        ).fetchone()
        if account is None:
            return
        if not account["enabled"]:
            raise RuntimeError("Conta local desativada")

        password1 = decrypt_secret(source["password1_encrypted"])
        password2 = decrypt_secret(account["password_encrypted"])

        ensure_maildir(account["email"])

        cmd = [
            "imapsync",
            "--host1",
            source["host1"],
            "--port1",
            str(source["port1"] or 993),
            "--user1",
            source["user1"],
            "--password1",
            password1,
            "--host2",
            DOVECOT_IMAP_HOST,
            "--port2",
            str(DOVECOT_IMAP_PORT),
            "--user2",
            account["email"],
            "--password2",
            password2,
            "--nossl2",
            "--notls2",
            "--syncinternaldates",
            "--subscribeall",
            "--nofoldersizes",
        ]

        security1 = (source["security1"] or "ssl").lower()
        if security1 == "ssl":
            cmd.append("--ssl1")
        elif security1 == "tls":
            cmd.append("--tls1")

        for folder in parse_folder_lines(source["include_folders"]):
            cmd.extend(["--folder", folder])
        for excluded in parse_folder_lines(source["exclude_folders"]):
            cmd.extend(["--exclude", excluded])

        extra_tokens = validate_extra_args(source["extra_args"] or "")
        cmd.extend(extra_tokens)

        for token in cmd:
            if is_forbidden_option(token):
                raise RuntimeError(f"Blocked dangerous imapsync option: {token}")

        cmd_redacted = redact_command_parts(cmd, password1, password2)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        log_dir = IMAPSYNC_LOG_ROOT / account["email"]
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file_path = str(log_dir / f"{ts}.log")

        conn.execute(
            """
            INSERT INTO source_runs
            (source_id, local_account_id, status, trigger_type, started_at, log_path, command_redacted)
            VALUES (?, ?, 'running', ?, ?, ?, ?)
            """,
            (source_id, account["id"], trigger_type, utcnow_iso(), log_file_path, cmd_redacted),
        )
        run_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        conn.commit()

        client = docker.from_env()
        container = get_running_container(client, IMAPSYNC_CONTAINER, wait_timeout=45)
        exec_id = client.api.exec_create(container.id, cmd=cmd)["Id"]

        with open(log_file_path, "w", encoding="utf-8") as log_file:
            log_file.write(f"# {utcnow_iso()} {cmd_redacted}\n")
            stream = client.api.exec_start(exec_id, stream=True, demux=True)
            for stdout_chunk, stderr_chunk in stream:
                if stdout_chunk:
                    piece = stdout_chunk.decode("utf-8", errors="replace")
                    log_file.write(redact_text(piece, [password1, password2]))
                    log_file.flush()
                if stderr_chunk:
                    piece = stderr_chunk.decode("utf-8", errors="replace")
                    log_file.write(redact_text(piece, [password1, password2]))
                    log_file.flush()

        inspect = client.api.exec_inspect(exec_id)
        exit_code = int(inspect.get("ExitCode", 1))
        duration = int(time.time() - start_ts)
        status = "success" if exit_code == 0 else "fail"
        log_size = Path(log_file_path).stat().st_size if Path(log_file_path).exists() else 0

        now = utcnow_iso()
        conn.execute(
            """
            UPDATE source_runs
            SET status = ?, finished_at = ?, duration_seconds = ?, exit_code = ?, log_size_bytes = ?
            WHERE id = ?
            """,
            (status, now, duration, exit_code, log_size, run_id),
        )
        conn.execute(
            "UPDATE source_accounts SET last_sync_at = ? WHERE id = ?",
            (now, source_id),
        )
        conn.commit()
    except Exception as exc:
        duration = int(time.time() - start_ts)
        err_text = str(exc)
        if run_id is None:
            source = conn.execute("SELECT * FROM source_accounts WHERE id = ?", (source_id,)).fetchone()
            local_account_id = source["local_account_id"] if source else 0
            conn.execute(
                """
                INSERT INTO source_runs
                (source_id, local_account_id, status, trigger_type, started_at, finished_at, duration_seconds, exit_code, log_path, error_message, command_redacted)
                VALUES (?, ?, 'fail', ?, ?, ?, ?, 1, ?, ?, '')
                """,
                (
                    source_id,
                    local_account_id,
                    trigger_type,
                    utcnow_iso(),
                    utcnow_iso(),
                    duration,
                    log_file_path,
                    err_text,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE source_runs
                SET status = 'fail', finished_at = ?, duration_seconds = ?, exit_code = 1, error_message = ?
                WHERE id = ?
                """,
                (utcnow_iso(), duration, err_text, run_id),
            )
        conn.commit()
    finally:
        conn.close()
        with running_sources_lock:
            running_sources.discard(source_id)


@app.before_request
def bootstrap():
    init_db()
    ensure_admin()
    start_scheduler_once()


@app.get("/login")
def login():
    if session.get("admin_id"):
        return redirect(url_for("index"))
    return render_template("login.html")


@app.post("/login")
def login_submit():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    conn = get_db()
    user = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
    if user and check_password_hash(user["password_hash"], password):
        session["admin_id"] = user["id"]
        session["admin_user"] = user["username"]
        return redirect(url_for("index"))
    flash("Credenciais inválidas", "error")
    return redirect(url_for("login"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(ValueError)
def handle_value_error(exc):
    flash(str(exc), "error")
    if session.get("admin_id"):
        return redirect(url_for("index"))
    return redirect(url_for("login"))


@app.errorhandler(RuntimeError)
def handle_runtime_error(exc):
    flash(str(exc), "error")
    if session.get("admin_id"):
        return redirect(url_for("index"))
    return redirect(url_for("login"))


@app.errorhandler(sqlite3.IntegrityError)
def handle_db_integrity_error(_exc):
    flash("Registro duplicado ou inválido para esta operação", "error")
    if session.get("admin_id"):
        return redirect(url_for("index"))
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    db = get_db()
    accounts_raw = db.execute(
        """
        SELECT a.*,
          (SELECT COUNT(*) FROM source_accounts s WHERE s.local_account_id = a.id) AS source_count
        FROM local_accounts a
        ORDER BY a.created_at DESC
        """
    ).fetchall()

    # Last sync per account (max finished_at from source_runs)
    last_sync_rows = db.execute(
        """
        SELECT s.local_account_id, MAX(r.finished_at) AS last_sync
        FROM source_runs r
        JOIN source_accounts s ON s.id = r.source_id
        WHERE r.finished_at IS NOT NULL
        GROUP BY s.local_account_id
        """
    ).fetchall()
    last_sync_map = {row["local_account_id"]: row["last_sync"] for row in last_sync_rows}

    # Build enriched account dicts (sqlite3.Row is read-only, so convert to dict)
    accounts = []
    for row in accounts_raw:
        a = dict(row)
        a["maildir_size"] = maildir_size_fmt(a["email"])
        raw_sync = last_sync_map.get(a["id"])
        a["last_sync"] = _fmt_brt(raw_sync) if raw_sync else None
        accounts.append(a)

    sources_raw = db.execute(
        """
        SELECT s.*, a.email AS local_email,
          (
            SELECT status FROM source_runs r
            WHERE r.source_id = s.id
            ORDER BY r.started_at DESC
            LIMIT 1
          ) AS last_status
        FROM source_accounts s
        JOIN local_accounts a ON a.id = s.local_account_id
        ORDER BY s.id DESC
        """
    ).fetchall()
    sources = []
    for row in sources_raw:
        s = dict(row)
        s.pop("password1_encrypted", None)  # never send to frontend
        if s.get("last_sync_at"):
            s["last_sync_at"] = _fmt_brt(s["last_sync_at"])
        # Next scheduled run
        job = scheduler.get_job(scheduler_job_id(s["id"]))
        if job and job.next_run_time:
            s["next_run"] = _fmt_brt(job.next_run_time.isoformat())
        else:
            s["next_run"] = None
        sources.append(s)
    runs = db.execute(
        """
        SELECT r.*, s.source_name, a.email AS local_email
        FROM source_runs r
        JOIN source_accounts s ON s.id = r.source_id
        JOIN local_accounts a ON a.id = r.local_account_id
        ORDER BY r.started_at DESC
        LIMIT 40
        """
    ).fetchall()
    return render_template(
        "index.html",
        accounts=accounts,
        sources=sources,
        runs=runs,
        roundcube_test_url=ROUND_CUBE_TEST_URL,
        roundcube_prod_url=ROUND_CUBE_PROD_URL,
    )


@app.get("/logs")
@login_required
def logs_page():
    db = get_db()
    runs_raw = db.execute(
        """
        SELECT r.*, s.source_name, s.host1, a.email AS local_email
        FROM source_runs r
        JOIN source_accounts s ON s.id = r.source_id
        JOIN local_accounts a ON a.id = r.local_account_id
        ORDER BY r.started_at DESC
        LIMIT 200
        """
    ).fetchall()
    runs = [dict(row) for row in runs_raw]
    for r in runs:
        if r.get("started_at"):
            r["started_at_fmt"] = _fmt_brt(r["started_at"])
        else:
            r["started_at_fmt"] = "—"
    return render_template("logs.html", runs=runs)


@app.post("/accounts")
@login_required
def create_account():
    email = request.form.get("email", "").strip().lower()
    validate_email(email)
    password = generate_password()
    password_hash = generate_sha512_crypt_hash(password)
    password_encrypted = encrypt_secret(password)

    ensure_maildir(email)

    db = get_db()
    now = utcnow_iso()
    db.execute(
        """
        INSERT INTO local_accounts (email, password_hash, password_encrypted, enabled, created_at, updated_at, last_password_reset_at)
        VALUES (?, ?, ?, 1, ?, ?, ?)
        """,
        (email, password_hash, password_encrypted, now, now, now),
    )
    sync_dovecot_users_file_or_rollback(db, email=email, password=password)
    flash(f"Conta criada: {email}. Senha (mostrar 1x): {password}", "success")
    return redirect(url_for("index"))


@app.post("/accounts/<int:account_id>/reset-password")
@login_required
def reset_account_password(account_id):
    db = get_db()
    account = db.execute("SELECT * FROM local_accounts WHERE id = ?", (account_id,)).fetchone()
    if account is None:
        flash("Conta não encontrada", "error")
        return redirect(url_for("index"))
    password = generate_password()
    password_hash = generate_sha512_crypt_hash(password)
    password_encrypted = encrypt_secret(password)
    now = utcnow_iso()
    db.execute(
        """
        UPDATE local_accounts
        SET password_hash = ?, password_encrypted = ?, updated_at = ?, last_password_reset_at = ?
        WHERE id = ?
        """,
        (password_hash, password_encrypted, now, now, account_id),
    )
    sync_dovecot_users_file_or_rollback(db, email=account["email"], password=password)
    flash(f"Senha resetada para {account['email']}. Senha (mostrar 1x): {password}", "success")
    return redirect(url_for("index"))


@app.post("/accounts/<int:account_id>/set-password")
@login_required
def set_account_password(account_id):
    db = get_db()
    account = db.execute("SELECT * FROM local_accounts WHERE id = ?", (account_id,)).fetchone()
    if account is None:
        flash("Conta não encontrada", "error")
        return redirect(url_for("index"))
    password = request.form.get("new_password", "")
    validate_local_password(password)
    password_hash = generate_sha512_crypt_hash(password)
    password_encrypted = encrypt_secret(password)
    now = utcnow_iso()
    db.execute(
        """
        UPDATE local_accounts
        SET password_hash = ?, password_encrypted = ?, updated_at = ?, last_password_reset_at = ?
        WHERE id = ?
        """,
        (password_hash, password_encrypted, now, now, account_id),
    )
    sync_dovecot_users_file_or_rollback(db, email=account["email"], password=password)
    flash(f"Senha alterada manualmente para {account['email']}", "success")
    return redirect(url_for("index"))


@app.post("/accounts/<int:account_id>/toggle")
@login_required
def toggle_account(account_id):
    db = get_db()
    account = db.execute("SELECT * FROM local_accounts WHERE id = ?", (account_id,)).fetchone()
    if account is None:
        flash("Conta não encontrada", "error")
        return redirect(url_for("index"))
    new_enabled = 0 if account["enabled"] else 1
    db.execute(
        "UPDATE local_accounts SET enabled = ?, updated_at = ? WHERE id = ?",
        (new_enabled, utcnow_iso(), account_id),
    )
    sync_dovecot_users_file_or_rollback(db)
    state = "ativada" if new_enabled else "desativada"
    flash(f"Conta {account['email']} {state}", "success")
    return redirect(url_for("index"))


@app.post("/accounts/<int:account_id>/delete")
@login_required
def delete_account(account_id):
    db = get_db()
    account = db.execute("SELECT * FROM local_accounts WHERE id = ?", (account_id,)).fetchone()
    if account is None:
        flash("Conta não encontrada", "error")
        return redirect(url_for("index"))
    db.execute("DELETE FROM local_accounts WHERE id = ?", (account_id,))
    sync_dovecot_users_file_or_rollback(db)
    flash(f"Conta removida do painel: {account['email']} (Maildir preservado)", "success")
    return redirect(url_for("index"))


@app.post("/sources")
@login_required
def create_source():
    db = get_db()
    local_account_id = int(request.form.get("local_account_id"))
    source_name = request.form.get("source_name", "").strip() or "source"
    host1 = request.form.get("host1", "").strip()
    port1 = int(request.form.get("port1", "993") or "993")
    security1 = request.form.get("security1", "ssl").strip().lower()
    user1 = request.form.get("user1", "").strip()
    password1 = request.form.get("password1", "")
    include_folders = request.form.get("include_folders", "")
    exclude_folders = request.form.get("exclude_folders", "")
    extra_args = request.form.get("extra_args", "")
    schedule_enabled = 1 if request.form.get("schedule_enabled") == "on" else 0
    schedule_mode = request.form.get("schedule_mode", "interval").strip().lower()
    schedule_value = request.form.get("schedule_value", "360").strip()

    validate_extra_args(extra_args)
    if schedule_mode == "cron":
        CronTrigger.from_crontab(schedule_value)
    else:
        if int(schedule_value or "360") < 1:
            raise ValueError("Intervalo em minutos deve ser >= 1")

    db.execute(
        """
        INSERT INTO source_accounts
        (local_account_id, source_name, host1, port1, security1, user1, password1_encrypted,
         include_folders, exclude_folders, extra_args, schedule_enabled, schedule_mode, schedule_value)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            local_account_id,
            source_name,
            host1,
            port1,
            security1,
            user1,
            encrypt_secret(password1),
            include_folders,
            exclude_folders,
            extra_args,
            schedule_enabled,
            schedule_mode,
            schedule_value,
        ),
    )
    db.commit()
    source_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    sync_scheduler_for_source(source_id)
    flash("Source IMAP criada", "success")
    return redirect(url_for("index"))


@app.post("/sources/<int:source_id>/update")
@login_required
def update_source(source_id):
    db = get_db()
    source = db.execute("SELECT * FROM source_accounts WHERE id = ?", (source_id,)).fetchone()
    if source is None:
        flash("Source não encontrada", "error")
        return redirect(url_for("index"))

    source_name = request.form.get("source_name", "").strip() or source["source_name"]
    host1 = request.form.get("host1", "").strip()
    port1 = int(request.form.get("port1", "993") or "993")
    security1 = request.form.get("security1", "ssl").strip().lower()
    user1 = request.form.get("user1", "").strip()
    include_folders = request.form.get("include_folders", "")
    exclude_folders = request.form.get("exclude_folders", "")
    extra_args = request.form.get("extra_args", "")
    schedule_enabled = 1 if request.form.get("schedule_enabled") == "on" else 0
    schedule_mode = request.form.get("schedule_mode", "interval").strip().lower()
    schedule_value = request.form.get("schedule_value", "360").strip()

    validate_extra_args(extra_args)
    if schedule_mode == "cron":
        CronTrigger.from_crontab(schedule_value)
    else:
        if int(schedule_value or "360") < 1:
            raise ValueError("Intervalo em minutos deve ser >= 1")

    password1 = request.form.get("password1", "")
    password_enc = source["password1_encrypted"] if not password1 else encrypt_secret(password1)

    db.execute(
        """
        UPDATE source_accounts
        SET source_name = ?, host1 = ?, port1 = ?, security1 = ?, user1 = ?, password1_encrypted = ?,
            include_folders = ?, exclude_folders = ?, extra_args = ?, schedule_enabled = ?, schedule_mode = ?, schedule_value = ?
        WHERE id = ?
        """,
        (
            source_name,
            host1,
            port1,
            security1,
            user1,
            password_enc,
            include_folders,
            exclude_folders,
            extra_args,
            schedule_enabled,
            schedule_mode,
            schedule_value,
            source_id,
        ),
    )
    db.commit()
    sync_scheduler_for_source(source_id)
    flash("Source atualizada", "success")
    return redirect(url_for("index"))


@app.post("/sources/<int:source_id>/toggle-schedule")
@login_required
def toggle_source_schedule(source_id):
    db = get_db()
    source = db.execute("SELECT * FROM source_accounts WHERE id = ?", (source_id,)).fetchone()
    if source is None:
        flash("Source não encontrada", "error")
        return redirect(url_for("index"))
    new_enabled = 0 if source["schedule_enabled"] else 1
    db.execute(
        "UPDATE source_accounts SET schedule_enabled = ? WHERE id = ?",
        (new_enabled, source_id),
    )
    db.commit()
    sync_scheduler_for_source(source_id)
    flash("Schedule atualizado", "success")
    return redirect(url_for("index"))


@app.post("/sources/<int:source_id>/import-now")
@login_required
def import_now(source_id):
    queued = schedule_import_async(source_id, "manual")
    if queued:
        flash("Importação iniciada", "success")
    else:
        flash("Já existe uma importação em execução para essa source", "error")
    return redirect(url_for("index"))


@app.post("/sources/<int:source_id>/delete")
@login_required
def delete_source(source_id):
    db = get_db()
    source = db.execute("SELECT * FROM source_accounts WHERE id = ?", (source_id,)).fetchone()
    if source is None:
        flash("Source não encontrada", "error")
        return redirect(url_for("index"))
    db.execute("DELETE FROM source_accounts WHERE id = ?", (source_id,))
    db.commit()
    job = scheduler.get_job(scheduler_job_id(source_id))
    if job:
        scheduler.remove_job(job.id)
    flash("Source removida", "success")
    return redirect(url_for("index"))


@app.get("/runs/<int:run_id>/log")
@login_required
def run_log(run_id):
    db = get_db()
    run = db.execute("SELECT * FROM source_runs WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        return Response("run not found\n", mimetype="text/plain", status=404)
    log_path = Path(run["log_path"])
    if not log_path.exists():
        return Response("log file not found\n", mimetype="text/plain", status=404)
    content = log_path.read_text(encoding="utf-8", errors="replace")
    return Response(content, mimetype="text/plain")


@app.post("/accounts/<int:account_id>/validate-credentials")
@login_required
def validate_credentials(account_id):
    db = get_db()
    account = db.execute("SELECT * FROM local_accounts WHERE id = ?", (account_id,)).fetchone()
    if account is None:
        flash("Conta não encontrada", "error")
        return redirect(url_for("index"))
    password = request.form.get("validate_password", "")
    if not password:
        flash("Informe a senha para validação", "error")
        return redirect(url_for("index"))
    try:
        # Always rebuild users file before testing to avoid stale/truncated legacy lines.
        rebuild_dovecot_users_file(db)

        validate_sha512_crypt_hash(account["password_hash"])
        local_hash_matches = sha512_crypt.verify(password, account["password_hash"])
        if not local_hash_matches:
            flash(
                "Senha informada não confere com o hash salvo no painel (DB). "
                "Use Alterar senha/Reset e tente novamente.",
                "error",
            )
            return redirect(url_for("index"))

        client = docker.from_env()
        container = get_running_container(client, DOVECOT_IMAP_HOST, wait_timeout=45)
        auth_code, output = exec_text(
            container, ["doveadm", "auth", "test", account["email"], password]
        )
        output = output.replace(password, "***")
        if auth_code == 0:
            flash(f"Credenciais válidas para {account['email']}. {output[:220]}", "success")
        else:
            pw_code, pw_output = exec_text(
                container,
                [
                    "doveadm",
                    "pw",
                    "-t",
                    f"{{SHA512-CRYPT}}{account['password_hash']}",
                    "-p",
                    password,
                ],
            )
            # Read the mounted users file from the panel container instead of relying on grep in dovecot image.
            users_line_found = False
            users_line_preview = ""
            users_hash_match = False
            users_hash_len = 0
            if DOVECOT_USERS_FILE.exists():
                for line in DOVECOT_USERS_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith(f"{account['email']}:"):
                        users_line_found = True
                        users_line_preview = line[:120]
                        stored = line.split(":", 1)[1].strip() if ":" in line else ""
                        prefix = "{SHA512-CRYPT}"
                        if stored.startswith(prefix):
                            file_hash = stored[len(prefix) :]
                            users_hash_len = len(file_hash)
                            users_hash_match = file_hash == account["password_hash"]
                        break

            conf_code, conf_output = exec_text(container, ["doveconf", "-n"])
            passdb_hint = ""
            if conf_output:
                for line in conf_output.splitlines():
                    stripped = line.strip()
                    if "passdb" in stripped or "passwd_file_path" in stripped:
                        passdb_hint = f"{passdb_hint} {stripped}".strip()
            diagnostics = []
            diagnostics.append(
                "hash-test-ok" if pw_code == 0 else f"hash-test-fail({pw_code})"
            )
            diagnostics.append(
                "user-line-found" if users_line_found else "user-line-missing"
            )
            if users_line_found:
                diagnostics.append(
                    "users-hash-match" if users_hash_match else "users-hash-mismatch"
                )
                if users_hash_len:
                    diagnostics.append(f"users-hash-len={users_hash_len}")
            if users_line_preview:
                diagnostics.append(f"users-hit={users_line_preview}")
            if pw_output:
                diagnostics.append(f"pw-test={pw_output[:120]}")
            if conf_code == 0 and passdb_hint:
                diagnostics.append(f"passdb={passdb_hint[:180]}")
            if "passdb static {" in conf_output:
                diagnostics.append("passdb-static-detected")
            flash(
                f"Falha no Dovecot para {account['email']} mesmo com hash local válido. "
                f"Verifique montagem de /etc/dovecot/users e config passdb. "
                f"{output[:180]} | {'; '.join(diagnostics)}",
                "error",
            )
    except (APIError, NotFound, Exception) as exc:
        flash(f"Erro ao validar credenciais: {exc}", "error")
    return redirect(url_for("index"))


@app.post("/dovecot/reload")
@login_required
def dovecot_reload():
    try:
        client = docker.from_env()
        container = get_running_container(client, DOVECOT_IMAP_HOST, wait_timeout=45)
        result = container.exec_run(cmd=["doveadm", "reload"])
        if result.exit_code == 0:
            flash("Dovecot recarregado com sucesso", "success")
        else:
            output = (result.output or b"").decode("utf-8", errors="replace")
            flash(f"Falha no reload dovecot: {output[:300]}", "error")
    except Exception as exc:
        flash(f"Falha no reload dovecot: {exc}", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
