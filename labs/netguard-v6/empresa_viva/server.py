"""Portal local corrigido. Não possui servidor de variante vulnerável, scanner ou shell."""
from __future__ import annotations

import hmac
import json
import mimetypes
import re
import socket
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .helpdesk import Helpdesk
from .reports import authentication_csv, report_html
from .scenarios import ROOT, catalog, compare
from .security import Denied

JSON_LIMIT = 16_384
STATIC = {"empresa-viva.html", "empresa-viva.css", "empresa-viva.js", "empresa-viva-core.js", "empresa-viva-views.js", "empresa-viva-books.js", "shield.svg"}
STATIC.update({"estudos.html", "styles.css", "app.js", "core.js", "wifi.js", "method.js", "method-view.js", "checkup.js",
               "operations.html", "operations.css", "operations.js", "operations-views.js", "operations-demo.js"})
PUBLIC_DATA = {"empresa-viva-missions.json", "controls.json", "cenario-loja.json", "cenario-escritorio.json", "defense-method.json",
               "wifi-checklist.json", "caso-financeiro-ficticio.csv", "caso-financeiro-ficticio.jsonl", "caso-benigno-ficticio.csv",
               "log-autenticacao-exemplo.csv", "inventario-exemplo.csv"}
REPORT_KEYS = {"run_id", "evidence_ids", "observation", "alternative", "correction", "limits", "next_step", "conclusion"}


def exact(payload, keys):
    if not isinstance(payload, dict) or set(payload) != set(keys):
        raise Denied(400, "Campos desconhecidos ou ausentes.")


def opaque(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise Denied(400, "Identificador inválido.")
    return value


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, store, port=8790):
        self.store, self.app = store, Helpdesk(store)
        self.request_slots, self.exercise_slot = threading.BoundedSemaphore(8), threading.Lock()
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(10)
        return request, address

    def process_request(self, request, address):
        if not self.request_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.request_slots.release()

    def handle_error(self, request, address):
        # Sem stack trace, caminho privado, corpo de requisição ou credencial em stdout.
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "NetGuardEmpresaViva/1"
    sys_version = ""

    def log_message(self, *args):
        pass

    def answer(self, value, status=200, *, content_type="application/json; charset=utf-8", cookie=None, filename=None):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False, allow_nan=False).encode() if content_type.startswith("application/json") else value.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def boundary(self, post=False):
        expected = f"127.0.0.1:{self.server.server_port}"
        if self.headers.get_all("Host") != [expected] or self.client_address[0] != "127.0.0.1":
            raise Denied(403, "Origem local inválida.")
        origin = self.headers.get_all("Origin")
        if origin and origin != [self.server.origin]:
            raise Denied(403, "Origem não permitida.")
        if post and origin != [self.server.origin]:
            raise Denied(403, "A ação exige a origem local do console.")
        if self.headers.get("Sec-Fetch-Site") in {"cross-site", "none"} and post:
            raise Denied(403, "Ação entre sites não permitida.")
        url = urlsplit(self.path)
        if url.scheme or url.netloc or url.query or url.fragment or "%" in url.path or ".." in url.path:
            raise Denied(400, "Caminho inválido.")
        return url.path

    def token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            return cookie["empresa_session"].value if "empresa_session" in cookie else ""
        except Exception:
            return ""

    def auth(self, csrf=False):
        session = self.server.app.session(self.token())
        if csrf:
            values = self.headers.get_all("X-NetGuard-CSRF")
            if not values or len(values) != 1 or not hmac.compare_digest(values[0], session["csrf"]):
                raise Denied(403, "Confirmação de sessão inválida.")
        return session

    def body(self):
        lengths = self.headers.get_all("Content-Length")
        if self.headers.get("Transfer-Encoding") or not lengths or len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= JSON_LIMIT:
            raise Denied(413, "Corpo da ação ausente ou maior que 16 KiB.")
        if self.headers.get("Content-Type") != "application/json":
            raise Denied(415, "A ação exige JSON.")
        raw = self.rfile.read(int(lengths[0]))
        if len(raw) != int(lengths[0]):
            raise Denied(400, "Corpo incompleto.")

        def pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = value
            return result

        try:
            return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
        except (ValueError, RecursionError, UnicodeError):
            raise Denied(400, "JSON inválido ou com campos duplicados.") from None

    def dispatch(self, post=False):
        try:
            path = self.boundary(post)
            if post:
                payload = self.body()
                self.post(path, payload)
            else:
                self.get(path)
        except Denied as error:
            self.answer({"error": error.message}, error.status)
        except (socket.timeout, BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:
            self.answer({"error": "Operação não concluída; confira o estado do laboratório local."}, 500)

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch(True)

    def get(self, path):
        if path == "/api/health":
            self.answer({"product": "netguard-empresa-viva", "mode": "local", "version": "1.1.0"})
            return
        if path == "/api/catalog":
            self.answer(catalog())
            return
        file = path.lstrip("/") or "empresa-viva.html"
        if file == "index.html":
            file = "empresa-viva.html"
        if file in STATIC or (file.startswith("data/") and file[5:] in PUBLIC_DATA):
            data = (ROOT/"web"/file).read_bytes()
            self.answer(data, content_type=(mimetypes.guess_type(file)[0] or "application/octet-stream")+"; charset=utf-8")
            return
        session = self.auth()
        identity = session["identity"]
        if path == "/api/session":
            self.answer({"identity": identity.public(), "csrf": session["csrf"]})
        elif path == "/api/tickets":
            self.answer({"tickets": self.server.app.list_tickets(identity)})
        elif (match := re.fullmatch(r"/api/tickets/([0-9]{1,10})", path)):
            self.answer(self.server.app.get_ticket(identity, int(match[1])))
        elif path == "/api/events":
            self.answer({"events": self.server.store.events(identity), "limit": "Até 200 eventos recentes; cliente vê sua conta alegada ou validada, administradora vê o recorte completo. Não identifica uma pessoa."})
        elif path == "/api/progress":
            self.answer({"runs": self.server.store.runs(identity.id), "reports": self.server.store.reports(identity.id)})
        elif (match := re.fullmatch(r"/api/runs/([a-f0-9]{32})(?:/(json|csv))?", path)):
            run = self.server.store.run(identity.id, match[1])
            if match[2] == "json":
                self.answer(run, filename="netguard-episodio.json")
            elif match[2] == "csv":
                self.answer(authentication_csv(run), content_type="text/csv; charset=utf-8", filename="netguard-autenticacao-ficticia.csv")
            else:
                self.answer(run)
        else:
            raise Denied(404, "Rota não encontrada.")

    def post(self, path, payload):
        if path == "/api/login":
            exact(payload, {"username", "password"})
            value, token = self.server.app.login(payload["username"], payload["password"], self.client_address[0])
            if self.token():
                self.server.app.sessions.remove(self.token())
            self.answer(value, cookie=f"empresa_session={token}; Path=/; HttpOnly; SameSite=Strict")
            return
        session = self.auth(csrf=True)
        identity = session["identity"]
        if path == "/api/logout":
            exact(payload, set())
            self.server.app.logout(self.token())
            self.answer({"ok": True}, cookie="empresa_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
        elif path == "/api/tickets":
            exact(payload, {"title", "body"})
            self.answer(self.server.app.create_ticket(identity, payload["title"], payload["body"]), 201)
        elif (match := re.fullmatch(r"/api/admin/tickets/([0-9]{1,10})/close", path)):
            exact(payload, set())
            self.answer(self.server.app.close_ticket(identity, int(match[1])))
        elif path == "/api/runs":
            exact(payload, {"mission_id", "transfer"})
            if not self.server.exercise_slot.acquire(blocking=False):
                raise Denied(409, "Há um episódio em execução. Aguarde; não envie requisições repetidas.")
            try:
                run = compare(payload["mission_id"], transfer=payload["transfer"])
                self.server.store.save_run(identity.id, run)
                self.answer(run, 201)
            finally:
                self.server.exercise_slot.release()
        elif path == "/api/reports":
            exact(payload, REPORT_KEYS)
            opaque(payload["run_id"])
            ids = payload["evidence_ids"]
            if not isinstance(ids, list) or not 1 <= len(ids) <= 30 or any(not isinstance(i, str) or not re.fullmatch(r"[a-f0-9]{32}", i) for i in ids):
                raise Denied(400, "Selecione de 1 a 30 evidências válidas.")
            report = self.server.store.save_report(identity.id, payload)
            run = self.server.store.run(identity.id, report["run_id"])
            self.answer({"report": report, "html": report_html(report, run)}, 201)
        else:
            raise Denied(404, "Rota não encontrada.")
