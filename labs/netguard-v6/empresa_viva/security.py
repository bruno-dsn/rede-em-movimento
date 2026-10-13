"""Identidade e sessão reais para o portal corrigido; não há senha padrão."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

ITERATIONS = 600_000


class Denied(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)


def password_hash(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ValueError("Use uma senha de 12 a 256 caracteres.")
    salt = secrets.token_hex(32)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()
    return f"pbkdf2-sha256${ITERATIONS}${salt}${digest}"


def password_matches(password, stored):
    if not isinstance(password, str) or len(password) > 256:
        return False
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != "pbkdf2-sha256" or int(iterations) != ITERATIONS:
            return False
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()
        return hmac.compare_digest(got, expected)
    except (ValueError, TypeError):
        return False


class LoginBudget:
    """Janela fixa: a tentativa negada não prolonga o bloqueio. Sem bloqueio global da conta."""
    def __init__(self, clock=time.monotonic, *, limit=5, window=60):
        self.clock, self.limit, self.window = clock, limit, window
        self.windows = {}
        self.source_attempts = {}

    def allow(self, source, username):
        now = self.clock()
        self.windows = {k: v for k, v in self.windows.items() if now-v[0] < self.window}
        self.source_attempts = {k: v for k, v in self.source_attempts.items() if now-v[0] < self.window}
        if len(self.windows) >= 256 and (source, username) not in self.windows:
            return False
        stamp, count = self.windows.get((source, username), (now, 0))
        global_stamp, total = self.source_attempts.get(source, (now, 0))
        if count >= self.limit or total >= 20:
            return False
        self.windows[(source, username)] = (stamp, count+1)
        self.source_attempts[source] = (global_stamp, total+1)
        return True

    def success(self, source, username):
        self.windows.pop((source, username), None)


@dataclass(frozen=True)
class Identity:
    id: str
    name: str
    role: str

    def public(self):
        return {"id": self.id, "name": self.name, "role": self.role}


class Sessions:
    def __init__(self, clock=time.monotonic):
        self.clock, self.values = clock, {}

    def create(self, identity):
        now = self.clock()
        self.values = {k: v for k, v in self.values.items() if now-v["created"] <= 14400 and now-v["seen"] <= 900}
        if len(self.values) >= 20:
            raise Denied(429, "Limite de sessões locais. Encerre uma sessão ou aguarde.")
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.values[self.key(token)] = {"identity": identity, "csrf": csrf, "created": now, "seen": now}
        return token, csrf

    @staticmethod
    def key(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def get(self, token):
        key = self.key(token)
        value = self.values.get(key)
        now = self.clock()
        if not value or now-value["created"] > 14400 or now-value["seen"] > 900:
            self.values.pop(key, None)
            raise Denied(401, "Entre no portal local.")
        value["seen"] = now
        return value

    def remove(self, token):
        self.values.pop(self.key(token), None)
