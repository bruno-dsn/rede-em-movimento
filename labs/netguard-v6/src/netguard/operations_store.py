"""Persistência local de evidências. Não contém serviço remoto ou telemetria externa."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import sqlite3
import threading
import uuid
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

VERSION = "4.0.0"
ITERATIONS = 600_000
MAX_EVENTS = 100_000
MAX_BACKUPS = 30
MAX_COPY = 1_048_576
COPY_QUOTA = 209_715_200
DISPOSITIONS = {"pending", "recognized", "investigate", "incident"}


def now_stamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def clean(value, limit=300):
    return "".join(c for c in str(value or "") if c >= " " and c != "\x7f")[:limit]


def private_directory(path):
    path = Path(path).expanduser().absolute()
    # Todas as partes existentes devem ser diretórios reais, sem redirecionamento.
    for parent in [path, *path.parents]:
        if parent.is_symlink() or getattr(parent, "is_junction", lambda: False)():
            raise ValueError("A pasta de dados não pode atravessar links ou junctions.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        if path.stat().st_uid != os.getuid():
            raise ValueError("A pasta de dados precisa pertencer ao usuário atual.")
        path.chmod(0o700)
    return path


def private_bytes(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def password_hash(password, salt=None):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ValueError("Use uma senha de 12 a 256 caracteres.")
    salt = salt or secrets.token_hex(32)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), ITERATIONS).hex()
    return f"pbkdf2-sha256${ITERATIONS}${salt}${digest}"


def password_matches(password, encoded):
    if not isinstance(password, str) or len(password) > 256:
        return False
    try:
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2-sha256" or int(rounds) != ITERATIONS or len(salt) != 64:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), ITERATIONS).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, AttributeError):
        return False


class Store:
    def __init__(self, directory):
        self.directory = private_directory(directory)
        self.copies = private_directory(self.directory / "copies")
        self.backups = private_directory(self.directory / "backups")
        self.path = self.directory / "operations.sqlite3"
        self.lock = threading.RLock()
        if not self.path.exists():
            private_bytes(self.path, b"")
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("Banco de dados precisa ser um arquivo local regular.")
        if os.name != "nt":
            self.path.chmod(0o600)
        with self.db() as db:
            db.executescript("""
            PRAGMA journal_mode=DELETE;
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, password TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(
              id INTEGER PRIMARY KEY AUTOINCREMENT, external_key TEXT UNIQUE,
              event_at TEXT NOT NULL, observed_at TEXT NOT NULL, kind TEXT NOT NULL,
              severity TEXT NOT NULL, source TEXT NOT NULL, ip TEXT NOT NULL,
              account TEXT NOT NULL, path TEXT NOT NULL, payload TEXT NOT NULL,
              previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS event_time ON events(event_at);
            CREATE INDEX IF NOT EXISTS event_kind ON events(kind, id);
            CREATE TABLE IF NOT EXISTS decisions(
              id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id),
              disposition TEXT NOT NULL, note TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS decision_event ON decisions(event_id,id);
            CREATE TABLE IF NOT EXISTS audit(
              id INTEGER PRIMARY KEY, action TEXT NOT NULL, actor TEXT NOT NULL,
              created_at TEXT NOT NULL, details TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS coverage(
              source TEXT PRIMARY KEY, status TEXT NOT NULL, detail TEXT NOT NULL, checked_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS files(
              root TEXT NOT NULL, path TEXT NOT NULL, digest TEXT NOT NULL,
              size INTEGER NOT NULL, PRIMARY KEY(root,path));
            CREATE TABLE IF NOT EXISTS backups(
              id TEXT PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL,
              size INTEGER NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS containment(
              id TEXT PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id),
              mode TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
              actor TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            """)
        if self.get("device") is None:
            self.set("device", {"id": str(uuid.uuid4()), "alias": "Meu computador",
                                "hostname": clean(platform.node()), "platform": platform.system()})

    @contextmanager
    def db(self):
        with self.lock:
            if self.path.is_symlink():
                raise ValueError("Banco redirecionado por link.")
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            try:
                with db:
                    yield db
            finally:
                db.close()

    def get(self, key, default=None):
        with self.db() as db:
            row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set(self, key, value):
        with self.db() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, canonical(value)))

    def init_user(self, username, password):
        if not isinstance(username, str) or not re.fullmatch(r"[a-zA-Z0-9._-]{3,40}", username):
            raise ValueError("Usuário: 3 a 40 letras, números, ponto, hífen ou underscore.")
        encoded = password_hash(password)
        with self.db() as db:
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                raise ValueError("Já existe um operador. Use o comando password para alterar a senha.")
            db.execute("INSERT INTO users VALUES(?,?)", (username, encoded))
        self.audit("operator_created", username)
        self.set("auth_revision", uuid.uuid4().hex)

    def has_user(self):
        with self.db() as db:
            return bool(db.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def verify_user(self, username, password):
        with self.db() as db:
            row = db.execute("SELECT password FROM users WHERE username=?", (username,)).fetchone()
        # Mesmo custo de derivação para usuário inexistente.
        dummy = f"pbkdf2-sha256${ITERATIONS}${'0'*64}${'0'*64}"
        valid = password_matches(password, row[0] if row else dummy)
        return bool(row and valid)

    def change_password(self, username, current, new):
        if not self.verify_user(username, current):
            raise ValueError("Credenciais inválidas.")
        encoded = password_hash(new)
        with self.db() as db:
            db.execute("UPDATE users SET password=? WHERE username=?", (encoded, username))
        self.audit("password_changed", username)
        self.set("auth_revision", uuid.uuid4().hex)

    def audit(self, action, actor="collector", details=None):
        with self.db() as db:
            db.execute("INSERT INTO audit(action,actor,created_at,details) VALUES(?,?,?,?)",
                       (clean(action, 80), clean(actor, 40), now_stamp(), canonical(details or {})))

    def coverage(self, source, status, detail):
        if status not in {"observed", "partial", "unavailable"}:
            raise ValueError("Cobertura inválida.")
        with self.db() as db:
            db.execute("INSERT OR REPLACE INTO coverage VALUES(?,?,?,?)",
                       (source, status, clean(detail, 800), now_stamp()))

    def add_event(self, kind, title, source, *, severity="info", event_at=None,
                  external_key=None, ip="", account="", path="", metadata=None):
        if severity not in {"info", "attention", "critical"}:
            raise ValueError("Prioridade inválida.")
        event_at = event_at or now_stamp()
        parsed = datetime.fromisoformat(event_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Evento precisa de fuso horário.")
        event_at = parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        event = {"device_id": self.get("device")["id"], "kind": clean(kind, 80), "title": clean(title, 300),
                 "source": clean(source, 100), "event_at": event_at, "observed_at": now_stamp(),
                 "severity": severity, "ip": clean(ip, 80), "account": clean(account, 160),
                 "path": clean(path, 1000), "metadata": metadata or {}, "mode": "observed"}
        payload = canonical(event)
        if len(payload.encode()) > 16_384:
            raise ValueError("Evidência excede o limite por evento.")
        with self.db() as db:
            if external_key and db.execute("SELECT id FROM events WHERE external_key=?", (external_key,)).fetchone():
                return None
            last = db.execute("SELECT id,event_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            if last and last[0] >= MAX_EVENTS:
                raise ValueError("Limite de 100 mil eventos atingido. Preserve/exporte e planeje a retenção.")
            previous = last[1] if last else "0"*64
            digest = hashlib.sha256((previous + payload).encode()).hexdigest()
            cursor = db.execute("""INSERT INTO events(external_key,event_at,observed_at,kind,severity,source,
                ip,account,path,payload,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (external_key, event_at, event["observed_at"], kind, severity, source, event["ip"],
                 event["account"], event["path"], payload, previous, digest))
            return cursor.lastrowid

    @staticmethod
    def event_row(row):
        return {**json.loads(row["payload"]), "id": row["id"], "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"], "disposition": row["disposition"] if "disposition" in row.keys() else "pending"}

    def events(self, search="", kind="", severity="", before=0, limit=50):
        clauses, params = [], []
        if search:
            escaped = clean(search, 200).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(e.ip LIKE ? ESCAPE '\\' OR e.account LIKE ? ESCAPE '\\' OR e.path LIKE ? ESCAPE '\\' OR e.kind LIKE ? ESCAPE '\\')")
            params += ["%"+escaped+"%"]*4
        if kind:
            clauses.append("e.kind=?")
            params.append(clean(kind, 80))
        if severity:
            clauses.append("e.severity=?")
            params.append(severity)
        if before:
            clauses.append("e.id<?")
            params.append(before)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = """SELECT e.*,COALESCE((SELECT disposition FROM decisions WHERE event_id=e.id
                 ORDER BY id DESC LIMIT 1),'pending') AS disposition FROM events e"""
        with self.db() as db:
            total = db.execute("SELECT COUNT(*) FROM events e"+where, params).fetchone()[0]
            rows = db.execute(sql+where+" ORDER BY e.id DESC LIMIT ?", [*params, min(max(limit, 1), 100)]).fetchall()
            return {"events": [self.event_row(row) for row in rows], "total": total,
                    "next_before": rows[-1]["id"] if rows and total > len(rows) else None}

    def investigation(self, event_id):
        with self.db() as db:
            row = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            if not row:
                raise ValueError("Evento não encontrado.")
            decisions = [dict(r) for r in db.execute("SELECT * FROM decisions WHERE event_id=? ORDER BY id DESC", (event_id,))]
            event = self.event_row(row)
            event["disposition"] = decisions[0]["disposition"] if decisions else "pending"
            # Mesmos campos em até 5 min, sem inferência de causalidade. Inclui observações antes/depois.
            stamp = datetime.fromisoformat(event["event_at"].replace("Z", "+00:00")).timestamp()
            related = []
            for other in db.execute("SELECT * FROM events WHERE id!=? AND (ip=? AND ip!='' OR account=? AND account!='' OR path=? AND path!='') ORDER BY id DESC LIMIT 500",
                                    (event_id, event["ip"], event["account"], event["path"])):
                when = datetime.fromisoformat(other["event_at"].replace("Z", "+00:00")).timestamp()
                if abs(when-stamp) <= 300:
                    related.append(self.event_row(other))
                if len(related) == 30:
                    break
            return {"event": event, "decisions": decisions, "related": related,
                    "related_limit": "Até 30 registros em 5 minutos com IP, conta ou caminho iguais; não comprova relação causal."}

    def decide(self, event_id, disposition, note, actor):
        if disposition not in DISPOSITIONS or not isinstance(note, str) or not 10 <= len(note.strip()) <= 2000:
            raise ValueError("Escolha um estado e registre de 10 a 2.000 caracteres de contexto.")
        with self.db() as db:
            if not db.execute("SELECT 1 FROM events WHERE id=?", (event_id,)).fetchone():
                raise ValueError("Evento não encontrado.")
            db.execute("INSERT INTO decisions(event_id,disposition,note,actor,created_at) VALUES(?,?,?,?,?)",
                       (event_id, disposition, clean(note, 2000), actor, now_stamp()))
        self.audit("investigation_updated", actor, {"event_id": event_id, "disposition": disposition})

    def verify_chain(self):
        previous, checked = "0"*64, 0
        with self.db() as db:
            for row in db.execute("SELECT * FROM events ORDER BY id"):
                expected = hashlib.sha256((previous+row["payload"]).encode()).hexdigest()
                if row["previous_hash"] != previous or not hmac.compare_digest(expected, row["event_hash"]):
                    return {"ok": False, "checked": checked, "first_invalid": row["id"]}
                previous, checked = row["event_hash"], checked+1
        return {"ok": True, "checked": checked, "head": previous,
                "limit": "Cadeia local sem assinatura ou âncora externa; não resiste à reescrita completa por administrador."}

    def capture(self, data, digest):
        if len(data) > MAX_COPY or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("A cópia excede 1 MiB ou mudou durante a coleta.")
        size = sum(p.stat().st_size for p in self.copies.glob("*.bin") if p.is_file() and not p.is_symlink())
        if size+len(data) > COPY_QUOTA:
            raise ValueError("Limite de 200 MiB de cópias atingido; a coleta de metadados continua.")
        identifier = uuid.uuid4().hex
        private_bytes(self.copies / (identifier+".bin"), data)
        return identifier

    def artifact(self, kind, identifier):
        if not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise ValueError("Identificador inválido.")
        if kind == "versions":
            path = self.copies / (identifier+".bin")
            with self.db() as db:
                row = db.execute("SELECT 1 FROM events WHERE payload LIKE ? LIMIT 1", ('%"copy_id":"'+identifier+'"%',)).fetchone()
            if not row:
                raise ValueError("Cópia não registrada em uma evidência.")
        else:
            with self.db() as db:
                row = db.execute("SELECT filename FROM backups WHERE id=?", (identifier,)).fetchone()
            if not row:
                raise ValueError("Pacote não encontrado.")
            path = self.backups / row[0]
        if path.is_symlink() or not path.is_file():
            raise ValueError("Artefato indisponível.")
        return path

    def backup(self, actor="collector"):
        with self.lock, self.db() as db:
            if db.execute("SELECT COUNT(*) FROM backups").fetchone()[0] >= MAX_BACKUPS:
                raise ValueError("Limite de 30 pacotes locais atingido; nenhum pacote foi apagado.")
            members = {
                "device.json": canonical(self.get("device")).encode(),
                "events.jsonl": ("\n".join(canonical(self.event_row(r)) for r in db.execute("SELECT * FROM events ORDER BY id"))+"\n").encode(),
                "investigations.json": canonical([dict(r) for r in db.execute("SELECT * FROM decisions ORDER BY id")]).encode(),
                "coverage.json": canonical([dict(r) for r in db.execute("SELECT * FROM coverage")]).encode(),
                "audit.jsonl": ("\n".join(canonical(dict(r)) for r in db.execute("SELECT * FROM audit ORDER BY id"))+"\n").encode(),
                "containment.json": canonical([dict(r) for r in db.execute("SELECT * FROM containment")]).encode(),
                "baseline.json": canonical([dict(r) for r in db.execute("SELECT * FROM files ORDER BY root,path")]).encode(),
            }
            captured = set()
            for row in db.execute("SELECT payload FROM events"):
                copy_id = json.loads(row[0])["metadata"].get("copy_id")
                if copy_id and re.fullmatch(r"[a-f0-9]{32}", copy_id):
                    captured.add(copy_id)
            included_bytes, skipped = 0, 0
            for identifier in sorted(captured):
                path = self.copies / (identifier+".bin")
                if path.is_symlink() or not path.is_file() or included_bytes+path.stat().st_size > 20_971_520:
                    skipped += 1
                    continue
                members["copies/"+identifier+".bin"] = path.read_bytes()
                included_bytes += path.stat().st_size
            manifest = {"format": "netguard-evidence", "schema_version": 1, "created_at": now_stamp(),
                        "chain": self.verify_chain(), "files": {key: hashlib.sha256(value).hexdigest() for key,value in members.items()},
                        "copies_omitted": skipped, "copy_limit_bytes": 20_971_520,
                        "limit": "Exportação local não assinada; não contém senhas nem sessões. Não é backup completo do computador."}
            members["manifest.json"] = canonical(manifest).encode()
            identifier = uuid.uuid4().hex
            filename = "evidence-"+identifier+".zip"
            path = self.backups / filename
            private_bytes(path, b"")
            try:
                with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for name,data in members.items():
                        archive.writestr(name, data)
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                created = now_stamp()
                db.execute("INSERT INTO backups VALUES(?,?,?,?,?)", (identifier, filename, digest, path.stat().st_size, created))
            except Exception:
                path.unlink(missing_ok=True)
                raise
        self.audit("evidence_backup", actor, {"id": identifier, "sha256": digest})
        self.set("last_backup_day", created[:10])
        return {"id": identifier, "filename": filename, "sha256": digest, "size": path.stat().st_size, "created_at": created}

    def summary(self):
        with self.db() as db:
            counts = {row[0]: row[1] for row in db.execute("SELECT severity,COUNT(*) FROM events GROUP BY severity")}
            return {"version": VERSION, "mode": "observed", "device": self.get("device"),
                    "heartbeat": self.get("heartbeat"), "counts": counts,
                    "coverage": [dict(r) for r in db.execute("SELECT * FROM coverage ORDER BY source")],
                    "backups": [dict(r) for r in db.execute("SELECT * FROM backups ORDER BY created_at DESC LIMIT 30")],
                    "containment": [dict(r) for r in db.execute("SELECT * FROM containment ORDER BY created_at DESC LIMIT 30")],
                    "settings": {k: self.get("config", {}).get(k) for k in ("interval", "snapshot_files", "business_start", "business_end")},
                    "watch_roots": [{"label": f"pasta-{i+1}", "path": p} for i,p in enumerate(self.get("config", {}).get("roots", []))],
                    "latest_checkup": self.get("latest_checkup")}
