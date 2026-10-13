"""Central de chamados corrigida. O servidor determina identidade, dono e papel."""
from __future__ import annotations

import secrets
import threading
import time

from .security import Denied, LoginBudget, Sessions, password_hash, password_matches


def ticket_id(value):
    if type(value) is not int or not 1 <= value <= 2_147_483_647:
        raise Denied(400, "ID de chamado inválido.")
    return value


class Helpdesk:
    def __init__(self, store, *, clock=time.monotonic, origin="observed_http"):
        self.store, self.origin = store, origin
        self.sessions, self.budget = Sessions(clock), LoginBudget(clock)
        self.lock = threading.RLock()
        self.dummy_hash = password_hash(secrets.token_urlsafe(24))

    def emit(self, actor, category, decision, **values):
        return self.store.event(actor, category, decision, origin=self.origin, **values)

    def login(self, username, password, source="127.0.0.1"):
        if not isinstance(username, str) or not 1 <= len(username) <= 40 or not isinstance(password, str) or len(password) > 256:
            raise Denied(400, "Campos de acesso inválidos.")
        with self.lock:
            user = self.store.user(username)
            actor = username if user else "anonymous"
            if not self.budget.allow(source, username):
                self.emit(actor, "login_limit", "denied", reason="temporary_source_budget")
                raise Denied(429, "Limite temporário de tentativas; aguarde a janela de 60 segundos.")
            matches = password_matches(password, user["password_hash"] if user else self.dummy_hash)
            if not user or not matches:
                self.emit(actor, "login", "denied", reason="credentials_not_validated")
                raise Denied(401, "Credenciais inválidas.")
            identity = self.store.identity(user)
            token, csrf = self.sessions.create(identity)
            self.budget.success(source, username)
            self.emit(identity.id, "login", "allowed", reason="credentials_validated")
            return {"identity": identity.public(), "csrf": csrf}, token

    def session(self, token):
        with self.lock:
            return self.sessions.get(token)

    def logout(self, token):
        with self.lock:
            value = self.sessions.get(token)
            self.sessions.remove(token)
            self.emit(value["identity"].id, "logout", "allowed", reason="session_revoked")

    @staticmethod
    def require(identity):
        if identity is None:
            raise Denied(401, "Entre no portal local.")

    def can_read(self, identity, ticket):
        return identity.role == "admin" or identity.id == ticket["owner"]

    def can_close(self, identity):
        return identity.role == "admin"

    def get_ticket(self, identity, identifier):
        self.require(identity)
        identifier = ticket_id(identifier)
        with self.store.db() as db:
            row = db.execute("SELECT id,owner,title,body,status FROM tickets WHERE id=?", (identifier,)).fetchone()
            record = dict(row) if row else None
            if not record or not self.can_read(identity, record):
                self.emit(identity.id, "ticket_read", "denied", resource=identifier, reason="not_found_or_not_authorized")
                raise Denied(404, "Chamado não encontrado para esta conta.")
            self.emit(identity.id, "ticket_read", "allowed", resource=identifier, reason="read_policy_allowed")
            return record

    def list_tickets(self, identity):
        self.require(identity)
        with self.store.db() as db:
            query, args = ("SELECT id,owner,title,status FROM tickets ORDER BY id", ()) if identity.role == "admin" else (
                "SELECT id,owner,title,status FROM tickets WHERE owner=? ORDER BY id", (identity.id,))
            return [dict(r) for r in db.execute(query, args)]

    def create_ticket(self, identity, title, body):
        self.require(identity)
        if not isinstance(title, str) or not 3 <= len(title.strip()) <= 100 or not isinstance(body, str) or not 10 <= len(body.strip()) <= 1000:
            raise Denied(400, "Título: 3–100 caracteres. Descrição: 10–1.000.")
        with self.store.db() as db:
            if db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] >= 500:
                raise Denied(409, "Limite de chamados do laboratório atingido.")
            result = db.execute("INSERT INTO tickets(owner,title,body) VALUES(?,?,?)", (identity.id, title.strip(), body.strip()))
            identifier = result.lastrowid
            self.emit(identity.id, "ticket_create", "allowed", resource=identifier, reason="owner_from_session")
            return dict(db.execute("SELECT id,owner,title,body,status FROM tickets WHERE id=?", (identifier,)).fetchone())

    def close_ticket(self, identity, identifier):
        self.require(identity)
        identifier = ticket_id(identifier)
        if not self.can_close(identity):
            self.emit(identity.id, "admin_close", "denied", resource=identifier, reason="admin_role_required")
            raise Denied(403, "A função exige papel administrativo.")
        with self.store.db() as db:
            if not db.execute("SELECT 1 FROM tickets WHERE id=?", (identifier,)).fetchone():
                raise Denied(404, "Chamado não encontrado.")
            db.execute("UPDATE tickets SET status='closed' WHERE id=?", (identifier,))
            self.emit(identity.id, "admin_close", "allowed", resource=identifier, reason="admin_policy_allowed")
            return {"id": identifier, "status": "closed"}
