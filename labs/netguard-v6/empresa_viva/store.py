"""Banco exclusivo do laboratório. Relatórios e execuções pertencem à identidade da sessão."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .security import Denied, Identity, password_hash

MAX_EVENTS = 20_000
MAX_RUNS = 200


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def private_directory(path):
    path = Path(path).expanduser().absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
            raise ValueError("A pasta de dados não pode atravessar links ou junctions.")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name != "nt":
        if path.stat().st_uid != os.getuid():
            raise ValueError("A pasta precisa pertencer ao usuário atual.")
        path.chmod(0o700)
    return path


class Store:
    def __init__(self, directory=None):
        self.directory = private_directory(directory) if directory else None
        self.path = self.directory/"cyberlab.sqlite3" if self.directory else None
        if self.path and self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
            raise ValueError("Banco local inválido.")
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(str(self.path) if self.path else ":memory:", check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        with self.db() as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL,
                  role TEXT NOT NULL CHECK(role IN ('customer','admin')), password_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY AUTOINCREMENT,
                  owner TEXT NOT NULL REFERENCES users(id), title TEXT NOT NULL, body TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')));
                CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                  id TEXT UNIQUE NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id),
                  mission_id TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id),
                  run_id TEXT NOT NULL REFERENCES runs(id), created_at TEXT NOT NULL, payload TEXT NOT NULL);
            """)
        if self.path and os.name != "nt":
            self.path.chmod(0o600)

    @contextmanager
    def db(self):
        with self.lock:
            try:
                yield self.connection
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise

    def close(self):
        with self.lock:
            self.connection.close()

    def initialized(self):
        with self.db() as db:
            return bool(db.execute("SELECT 1 FROM users LIMIT 1").fetchone())

    def initialize(self, passwords, *, hashes=None):
        if set(passwords) != {"lia", "rafa", "admin"}:
            raise ValueError("São necessárias as três contas fictícias.")
        encoded = hashes or {key: password_hash(value) for key, value in passwords.items()}
        with self.db() as db:
            if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise ValueError("Dados já inicializados. Nenhum dado foi substituído.")
            for user, name, role in (("lia", "Lia · cliente fictícia", "customer"),
                                     ("rafa", "Rafael · cliente fictício", "customer"),
                                     ("admin", "Joana · administradora fictícia", "admin")):
                db.execute("INSERT INTO users VALUES(?,?,?,?)", (user, name, role, encoded[user]))
            self.seed_tickets(db)

    @staticmethod
    def seed_tickets(db):
        db.execute("INSERT INTO tickets(id,owner,title,body) VALUES(101,'lia','Acesso ao portal','O acesso voltou depois de corrigir um erro de digitação.')")
        db.execute("INSERT INTO tickets(id,owner,title,body) VALUES(202,'rafa','Pedido privado de Rafael','Este conteúdo pertence apenas ao cliente Rafael e à administração autorizada.')")

    def user(self, username):
        with self.db() as db:
            row = db.execute("SELECT * FROM users WHERE id=?", (username,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def identity(user):
        return Identity(user["id"], user["name"], user["role"])

    def event(self, actor, category, decision, *, resource="", reason="", correlation_id=None, origin="observed_http", at=None):
        record = {"id": uuid.uuid4().hex, "run_id": None, "timestamp": at or stamp(), "observed_at": stamp(),
                  "origin": origin, "category": category, "actor": actor, "resource": str(resource),
                  "decision": decision, "reason": reason, "correlation_id": correlation_id or uuid.uuid4().hex}
        with self.db() as db:
            if db.execute("SELECT COUNT(*) FROM events").fetchone()[0] >= MAX_EVENTS:
                raise Denied(409, "Limite de registros locais atingido; preserve e revise a retenção.")
            db.execute("INSERT INTO events(id,actor,payload) VALUES(?,?,?)", (record["id"], actor, dumps(record)))
        return record

    def events(self, identity):
        with self.db() as db:
            query, args = ("SELECT payload FROM events ORDER BY seq DESC LIMIT 200", ()) if identity.role == "admin" else (
                "SELECT payload FROM events WHERE actor=? ORDER BY seq DESC LIMIT 200", (identity.id,))
            return [json.loads(row[0]) for row in reversed(db.execute(query, args).fetchall())]

    def save_run(self, owner, run):
        with self.db() as db:
            if db.execute("SELECT COUNT(*) FROM runs WHERE owner=?", (owner,)).fetchone()[0] >= MAX_RUNS:
                raise Denied(409, "Limite de 200 execuções por conta; preserve seus relatórios.")
            db.execute("INSERT INTO runs VALUES(?,?,?,?,?)", (run["id"], owner, run["mission_id"], run["started_at"], dumps(run)))

    def run(self, owner, identifier):
        with self.db() as db:
            row = db.execute("SELECT payload FROM runs WHERE id=? AND owner=?", (identifier, owner)).fetchone()
            if not row:
                raise Denied(404, "Execução não encontrada para esta conta.")
            return json.loads(row[0])

    def runs(self, owner):
        with self.db() as db:
            return [{"id": r[0], "mission_id": r[1], "created_at": r[2]} for r in db.execute(
                "SELECT id,mission_id,created_at FROM runs WHERE owner=? ORDER BY created_at DESC", (owner,))]

    def save_report(self, owner, payload):
        run = self.run(owner, payload["run_id"])
        all_ids = {e["id"] for part in run["variants"] for e in part["events"]}
        if not payload["evidence_ids"] or not set(payload["evidence_ids"]).issubset(all_ids):
            raise Denied(400, "Selecione evidências da própria execução.")
        for key in ("observation", "alternative", "correction", "limits", "next_step"):
            value = payload[key]
            if not isinstance(value, str) or not 20 <= len(value.strip()) <= 1500:
                raise Denied(400, "Cada campo do relatório precisa de 20 a 1.500 caracteres.")
        if payload["conclusion"] not in {"legitimate", "suspected", "confirmed_lab_flaw"}:
            raise Denied(400, "Conclusão inválida.")
        report = {**payload, "id": uuid.uuid4().hex, "created_at": stamp(), "mission_id": run["mission_id"],
                  "source": run["mode"], "code_sha256": run["code_sha256"], "checks": run["checks"],
                  "assessment_limit": "Validação de estrutura e vínculo das evidências; não avalia a qualidade da conclusão nem certifica aprendizado."}
        with self.db() as db:
            if db.execute("SELECT COUNT(*) FROM reports WHERE owner=?", (owner,)).fetchone()[0] >= 500:
                raise Denied(409, "Limite de relatórios atingido; exporte seus registros.")
            db.execute("INSERT INTO reports VALUES(?,?,?,?,?)", (report["id"], owner, run["id"], report["created_at"], dumps(report)))
        return report

    def reports(self, owner):
        with self.db() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT payload FROM reports WHERE owner=? ORDER BY created_at DESC", (owner,))]
