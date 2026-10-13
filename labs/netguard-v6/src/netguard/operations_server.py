"""Console HTTP restrito a 127.0.0.1, com sessão, CSRF e login no servidor."""
from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import re
import secrets
import sqlite3
import threading
import time
from collections import deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .operations_containment import Containment
from .business import Business
from .operations_monitor import Monitor
from .operations_store import VERSION, canonical

COOKIE = "netguard_session"
STATIC = {"continuity.js", "continuity.css", "continuity-core.js", "continuity-views.js", "academy.js", "empresa-viva.html", "empresa-viva-books.js", "estudos.html", "empresa-viva.css", "empresa-viva.js", "empresa-viva-core.js", "empresa-viva-views.js", "operations.html", "operations.css", "operations.js", "operations-views.js", "operations-demo.js", "shield.svg",
          "index.html", "styles.css", "app.js", "core.js", "wifi.js", "method.js", "method-view.js", "checkup.js"}
PUBLIC_DATA = {"empresa-viva-missions.json","controls.json", "cenario-loja.json", "cenario-escritorio.json", "defense-method.json",
               "wifi-checklist.json", "caso-financeiro-ficticio.csv", "caso-financeiro-ficticio.jsonl",
               "caso-benigno-ficticio.csv", "log-autenticacao-exemplo.csv", "inventario-exemplo.csv"}
CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class Auth:
    def __init__(self, store, clock=time.monotonic):
        self.store, self.clock = store, clock
        self.lock = threading.RLock()
        self.sessions = {}
        self.attempts = deque()
        self.failures = deque()

    def login(self, username, password):
        with self.lock:
            now = self.clock()
            while self.attempts and self.attempts[0] < now-60:
                self.attempts.popleft()
            while self.failures and self.failures[0] < now-300:
                self.failures.popleft()
            if len(self.attempts) >= 20 or len(self.failures) >= 5:
                raise APIError(429, "Muitas tentativas. Aguarde até cinco minutos antes de tentar novamente.")
            self.attempts.append(now)
            if not isinstance(username, str) or not re.fullmatch(r"[a-zA-Z0-9._-]{3,40}", username) or not isinstance(password, str):
                raise APIError(400, "Credenciais inválidas.")
            if not self.store.verify_user(username, password):
                self.failures.append(now)
                self.store.audit("login_failed", "anonymous")
                raise APIError(401, "Credenciais inválidas.")
            token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
            self.sessions = {k:v for k,v in self.sessions.items() if now-v["created"] < 28800 and now-v["last"] < 1800}
            if len(self.sessions) >= 20:
                oldest = min(self.sessions, key=lambda k: self.sessions[k]["created"])
                del self.sessions[oldest]
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = {"username": username, "csrf": csrf, "created": now, "last": now,
                                                                       "revision": self.store.get("auth_revision")}
            self.store.audit("login_succeeded", username)
            return token, {"username": username, "csrf": csrf}

    def session(self, token):
        with self.lock:
            identifier = hashlib.sha256(token.encode()).hexdigest()
            session = self.sessions.get(identifier)
            now = self.clock()
            if not session or now-session["created"] >= 28800 or now-session["last"] >= 1800 or session["revision"] != self.store.get("auth_revision"):
                self.sessions.pop(identifier, None)
                raise APIError(401, "Entre novamente para continuar.")
            session["last"] = now
            return session.copy()

    def logout(self, token):
        with self.lock:
            self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)

    def clear(self):
        with self.lock:
            self.sessions.clear()


class OperationsServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, store, port=8787, *, monitor=None, enable_containment=False, web=None):
        self.store, self.auth = store, Auth(store)
        self.monitor = monitor or Monitor(store)
        self.business = Business(store)
        self.containment = Containment(store, enabled=enable_containment)
        self.action_lock = threading.Lock()
        self.checkup_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(8)
        self.web = Path(web) if web else Path(__file__).resolve().parents[2]/"web"
        super().__init__(("127.0.0.1", port), Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(10)
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def dashboard(self):
        return {**self.store.summary(), "capabilities": self.containment.capabilities()}


class Handler(BaseHTTPRequestHandler):
    server_version = "NetGuard"
    sys_version = ""

    def log_message(self, *args):
        pass  # requisições/cookies e parâmetros não são registrados por http.server

    def send_data(self, status, data, content_type="application/json; charset=utf-8", *, cookie=None, filename=None):
        if not isinstance(data, bytes):
            data = canonical(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", CSP if "text/html" in content_type else "default-src 'none'; frame-ancestors 'none'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if filename:
            self.send_header("Content-Disposition", 'attachment; filename="'+filename+'"')
        self.end_headers()
        self.wfile.write(data)

    def boundary(self, mutation=False):
        expected = "127.0.0.1:"+str(self.server.server_port)
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0] != expected or not self.path.startswith("/") or self.path.startswith("//"):
            raise APIError(403, "Acesso restrito ao endereço local informado pelo console.")
        if self.headers.get("Sec-Fetch-Site") in {"cross-site", "same-site"}:
            raise APIError(403, "Origem externa não permitida.")
        if mutation and self.headers.get("Origin") != "http://"+expected:
            raise APIError(403, "Origem da operação não permitida.")
        return urlsplit(self.path)

    def token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return ""
        return cookie[COOKIE].value if COOKIE in cookie else ""

    def session(self, mutation=False):
        session = self.server.auth.session(self.token())
        if mutation and not hmac.compare_digest(self.headers.get("X-NetGuard-CSRF", ""), session["csrf"]):
            raise APIError(403, "Confirmação da sessão ausente ou inválida.")
        return session

    def body(self, required):
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            raise APIError(400, "Tamanho de requisição inválido.")
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            raise APIError(415, "Envie JSON.")
        try:
            length = int(self.headers["Content-Length"])
            if not 2 <= length <= 65_536:
                raise ValueError()
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError()
            def unique(pairs):
                obj = {}
                for key,value in pairs:
                    if key in obj:
                        raise ValueError()
                    obj[key] = value
                return obj
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if not isinstance(value, dict) or set(value) != set(required):
                raise ValueError()
            return value
        except (ValueError, UnicodeError, RecursionError):
            raise APIError(400, "JSON inválido ou campos inesperados.") from None

    @staticmethod
    def event_id(value):
        if type(value) is not int or not 1 <= value <= 100_000:
            raise APIError(400, "Identificador de evento inválido.")
        return value

    def do_GET(self):
        try:
            url = self.boundary()
            path = url.path
            if path == "/api/health":
                self.send_data(200, {"product": "netguard-operations", "version": VERSION, "mode": "local", "initialized": self.server.store.has_user()})
                return
            if path.startswith("/api/"):
                session = self.session()
                if path == "/api/session":
                    result = {"username": session["username"], "csrf": session["csrf"]}
                elif path == "/api/dashboard":
                    result = self.server.dashboard()
                elif path == "/api/business":
                    result = self.server.business.summary()
                elif path == "/api/events":
                    params = parse_qs(url.query, keep_blank_values=True, max_num_fields=10)
                    if any(len(v) != 1 for v in params.values()) or set(params)-{"search", "kind", "severity", "before"}:
                        raise APIError(400, "Filtro inválido.")
                    values = {k: v[0] for k,v in params.items()}
                    before = int(values.pop("before", "0") or "0")
                    if before < 0 or before > 100001:
                        raise ValueError("Cursor inválido.")
                    result = self.server.store.events(**values, before=before)
                elif re.fullmatch(r"/api/events/[1-9][0-9]{0,5}", path):
                    result = self.server.store.investigation(int(path.split("/")[-1]))
                elif path == "/api/integrity":
                    result = self.server.store.verify_chain()
                elif re.fullmatch(r"/api/(backups|versions)/[a-f0-9]{32}", path):
                    kind, identifier = path.split("/")[2:]
                    file = self.server.store.artifact(kind, identifier)
                    if file.stat().st_size > 100_000_000:
                        raise ValueError("Artefato excede o limite de download.")
                    self.send_data(200, file.read_bytes(), "application/octet-stream", filename=file.name)
                    return
                else:
                    raise APIError(404, "Recurso não encontrado.")
                self.send_data(200, result)
                return
            name = path.lstrip("/") or "operations.html"
            if name not in STATIC and not (name.startswith("data/") and name[5:] in PUBLIC_DATA):
                raise APIError(404, "Arquivo não encontrado.")
            file = self.server.web/name
            if file.is_symlink() or not file.is_file():
                raise APIError(404, "Arquivo não encontrado.")
            mime = {".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml"}.get(file.suffix) or mimetypes.guess_type(file.name)[0] or "application/octet-stream"
            self.send_data(200, file.read_bytes(), mime+"; charset=utf-8")
        except APIError as ex:
            self.send_data(ex.status, {"error": ex.message})
        except ValueError as ex:
            self.send_data(400, {"error": str(ex)[:400]})
        except (OSError, sqlite3.Error):
            self.send_data(503, {"error": "Consulta local indisponível. Revise armazenamento e permissões."})

    def do_POST(self):
        try:
            url = self.boundary(mutation=True)
            if url.query:
                raise APIError(400, "Parâmetros inesperados.")
            path, cookie = url.path, None
            if path == "/api/login":
                body = self.body({"username", "password"})
                token, result = self.server.auth.login(body["username"], body["password"])
                cookie = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800"
            else:
                session = self.session(mutation=True)
                actor = session["username"]
                if path == "/api/logout":
                    self.body(set())
                    self.server.auth.logout(self.token())
                    self.server.store.audit("logout", actor)
                    cookie = f"{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
                    result = {"ok": True}
                elif path == "/api/collect":
                    self.body(set())
                    self.server.monitor.cycle()
                    self.server.store.audit("manual_collection", actor)
                    result = self.server.dashboard()
                elif path == "/api/checkup":
                    self.body(set())
                    if not self.server.checkup_lock.acquire(blocking=False):
                        raise ValueError("Check-up em andamento.")
                    try:
                        result = self.server.monitor.checkup()
                    finally:
                        self.server.checkup_lock.release()
                    self.server.store.audit("manual_checkup", actor)
                elif path == "/api/investigations":
                    body = self.body({"event_id", "disposition", "note"})
                    event_id = self.event_id(body["event_id"])
                    self.server.store.decide(event_id, body["disposition"], body["note"], actor)
                    result = self.server.store.investigation(event_id)
                elif path == "/api/business/profile":
                    body = self.body({"name", "sector", "owner", "rpo_hours", "rto_minutes", "assets"})
                    result = self.server.business.profile(body, actor)
                elif path == "/api/business/review":
                    body = self.body({"control", "status", "owner", "note"})
                    result = self.server.business.review(**body, actor=actor)
                elif path == "/api/business/snapshot":
                    self.body(set())
                    result = self.server.business.snapshot(actor)
                elif path == "/api/business/restore":
                    body = self.body({"id"})
                    result = self.server.business.restore(body["id"], actor)
                elif path == "/api/backups":
                    self.body(set())
                    result = self.server.store.backup(actor)
                elif path.startswith("/api/containment/"):
                    with self.server.action_lock:
                        if path == "/api/containment/plan":
                            body = self.body({"event_id", "mode"})
                            result = self.server.containment.plan(self.event_id(body["event_id"]), body["mode"], actor)
                        elif path == "/api/containment/apply":
                            body = self.body({"id", "password", "confirmation", "impact_acknowledged"})
                            result = self.server.containment.apply(body["id"], actor, body["password"], body["confirmation"], body["impact_acknowledged"])
                        elif path == "/api/containment/release":
                            body = self.body({"id", "password", "note"})
                            result = self.server.containment.release(body["id"], actor, body["password"], body["note"])
                        elif path == "/api/containment/cancel":
                            body = self.body({"id"})
                            result = self.server.containment.cancel(body["id"], actor)
                        else:
                            raise APIError(404, "Operação não encontrada.")
                elif path == "/api/password":
                    body = self.body({"current", "new"})
                    self.server.store.change_password(actor, body["current"], body["new"])
                    self.server.auth.clear()
                    cookie = f"{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
                    result = {"ok": True, "message": "Senha alterada. Todas as sessões foram encerradas."}
                else:
                    raise APIError(404, "Operação não encontrada.")
            self.send_data(200, result, cookie=cookie)
        except APIError as ex:
            self.send_data(ex.status, {"error": ex.message})
        except (ValueError, TypeError, KeyError) as ex:
            self.send_data(400, {"error": str(ex)[:400] if isinstance(ex, ValueError) else "Campos inválidos."})
        except (OSError, sqlite3.Error):
            self.send_data(503, {"error": "Operação não concluída. Confira armazenamento e estado das fontes."})
