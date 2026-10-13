"""Episódios de escopo fixo. Fontes e limites acompanham cada execução."""
from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import VERSION
from .book_models import BOOK_MISSIONS
from .book_scenarios import book_run
from .helpdesk import Helpdesk
from .lessons import MissingAdminCheck, MissingLoginLimit, MissingOwnerCheck
from .security import Denied, password_hash
from .store import Store, stamp

ROOT = Path(__file__).resolve().parents[1]
MISSION_IDS = ("login", "ownership", "admin", *BOOK_MISSIONS)
LIMITS = {"login": 18, "ownership": 12, "admin": 12}
BASE_TIME = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def catalog():
    value = json.loads((ROOT/"web"/"data"/"empresa-viva-missions.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"version", "company", "missions", "glossary", "roadmap", "reading"}:
        raise ValueError("Catálogo inválido.")
    if [m["id"] for m in value["missions"]] != list(MISSION_IDS):
        raise ValueError("As missões precisam do contrato conhecido.")
    required = {"id", "number", "title", "brief", "objective", "prerequisites", "scope", "hypotheses", "steps",
                "evidence", "hints", "cause", "correction", "expected", "transfer", "concepts", "references"}
    for mission in value["missions"]:
        if set(mission) != required or len(mission["hints"]) != 3:
            raise ValueError("Missão fora do contrato.")
        for key in ("brief", "title", "cause", "correction", "transfer"):
            if not isinstance(mission[key], str) or not mission[key]:
                raise ValueError("Texto necessário ausente.")
        for key in ("prerequisites", "hypotheses", "steps", "evidence", "hints", "expected", "concepts", "references"):
            if not isinstance(mission[key], list) or not mission[key] or not all(isinstance(t, str) and t for t in mission[key]):
                raise ValueError("Lista da missão inválida.")
    book_keys = {"id", "title", "author", "edition", "year", "chapters", "mission_ids", "focus"}
    if not isinstance(value["reading"], list) or {b.get("id") for b in value["reading"] if isinstance(b, dict)} != {"web", "kali", "management", "warfare"} or len(value["reading"]) != 4:
        raise ValueError("Referências dos livros fora do contrato.")
    for book in value["reading"]:
        if not isinstance(book, dict) or set(book) != book_keys or type(book["year"]) is not int:
            raise ValueError("Referência inválida.")
        if not isinstance(book["mission_ids"], list) or not book["mission_ids"] or any(mid not in MISSION_IDS for mid in book["mission_ids"]):
            raise ValueError("Referência sem missão conhecida.")
        if any(not isinstance(book[key], str) or not book[key] for key in ("id", "title", "author", "edition", "chapters", "focus")):
            raise ValueError("Texto da referência ausente.")
    return value


def code_sha256():
    digest = hashlib.sha256()
    for name in ("helpdesk.py", "lessons.py", "scenarios.py", "security.py", "store.py", "book_models.py", "book_scenarios.py"):
        digest.update(name.encode())
        digest.update((Path(__file__).parent/name).read_bytes())
    return digest.hexdigest()


def snippets(mission):
    return {
        "login": {"before": "# lessons.py: _NoLimitForFixedLesson\ndef allow(self, source, username):\n    return True",
                  "after": "# security.py: LoginBudget.allow\nif count >= self.limit or total >= 20:\n    return False\nself.windows[(source, username)] = (stamp, count+1)"},
        "ownership": {"before": "# lessons.py: MissingOwnerCheck\ndef can_read(self, identity, ticket):\n    return True",
                      "after": "# helpdesk.py: Helpdesk.can_read\nreturn identity.role == 'admin' or identity.id == ticket['owner']"},
        "admin": {"before": "# lessons.py: MissingAdminCheck\ndef can_close(self, identity):\n    return True",
                  "after": "# helpdesk.py: Helpdesk.can_close\nreturn identity.role == 'admin'\n# close_ticket verifica o papel antes de alterar o chamado."},
    }[mission]


def compare(mission, *, transfer=False):
    if not isinstance(mission, str) or mission not in MISSION_IDS or type(transfer) is not bool:
        raise Denied(400, "Missão ou caso desconhecido. O laboratório não aceita alvos, URLs ou comandos.")
    if mission in BOOK_MISSIONS:
        return book_run(mission, transfer, code_sha256())
    started, identifier = stamp(), uuid.uuid4().hex
    credentials = {k: secrets.token_urlsafe(24) for k in ("lia", "rafa", "admin")}
    hashes = {k: password_hash(v) for k, v in credentials.items()}
    # Não há dicionário de senhas, descoberta de destinos ou tentativas em serviços externos.
    factory = {"login": MissingLoginLimit, "ownership": MissingOwnerCheck, "admin": MissingAdminCheck}[mission]
    variants, checks = [], []
    for variant, app_type in (("before", factory), ("after", Helpdesk)):
        store = Store()
        clock = [0.0]
        store.initialize(credentials, hashes=hashes)
        if transfer:
            with store.db() as db:
                db.execute("UPDATE tickets SET id=707 WHERE id=202")
        app = app_type(store, clock=lambda: clock[0], origin="observed_python")
        observations, count = [], [0]

        def observe(label, fn, *, request, actor="anonymous", resource="", expect=None):
            if count[0] >= LIMITS[mission]:
                raise RuntimeError("Orçamento fixo de operações excedido.")
            count[0] += 1
            try:
                data = fn()
                status = 200
            except Denied as error:
                status, data = error.status, {"message": error.message}
            correlation = uuid.uuid4().hex
            row = store.event(actor, "probe", "allowed" if status == 200 else "denied", resource=resource,
                              reason=label, origin="observed_python", correlation_id=correlation,
                              at=(BASE_TIME+timedelta(seconds=count[0])).isoformat())
            observations.append({"label": label, "status": status, "request": request, "actor": actor,
                                 "resource": str(resource), "data": data, "event_id": row["id"], "correlation_id": correlation})
            if expect is not None:
                checks.append({"name": f"{variant}: {label}", "expected": expect, "actual": status, "passed": status == expect})
            clock[0] += 1
            return data

        def login(actor):
            value, token = app.login(actor, credentials[actor], "192.0.2.10")
            return app.session(token)["identity"]

        if mission == "login":
            benign_count = 1 if transfer else 2
            for i in range(benign_count):
                observe(f"Erro legítimo {i+1}", lambda: app.login("lia", "valor-incorreto", "192.0.2.10"),
                        request="POST /api/login · valor de senha omitido", actor="lia", expect=401)
            observe("Acesso legítimo após correção", lambda: app.login("lia", credentials["lia"], "192.0.2.10")[0]["identity"],
                    request="POST /api/login · valor de senha omitido", actor="lia", expect=200)
            for i in range(8):
                observe(f"Tentativa controlada {i+1}", lambda: app.login("rafa", "valor-incorreto", "192.0.2.50"),
                        request="POST /api/login · origem fictícia 192.0.2.50", actor="rafa",
                        expect=429 if variant == "after" and i >= 5 else 401)
            observe("Outra origem: cliente legítimo", lambda: app.login("rafa", credentials["rafa"], "192.0.2.60")[0]["identity"],
                    request="POST /api/login · origem fictícia 192.0.2.60", actor="rafa", expect=200)
        else:
            liaison, other, admin = login("lia"), login("rafa"), login("admin")
            target = 707 if transfer else 202
            if mission == "ownership":
                observe("Anônimo tenta consultar", lambda: app.get_ticket(None, target), request=f"GET /api/tickets/{target}", resource=target, expect=401)
                observe("Proprietário consulta", lambda: app.get_ticket(other, target), request=f"GET /api/tickets/{target}", actor="rafa", resource=target, expect=200)
                observe("Outro cliente consulta", lambda: app.get_ticket(liaison, target), request=f"GET /api/tickets/{target}", actor="lia", resource=target, expect=200 if variant == "before" else 404)
                observe("Administradora autorizada consulta", lambda: app.get_ticket(admin, target), request=f"GET /api/tickets/{target}", actor="admin", resource=target, expect=200)
                observe("Cliente consulta o próprio chamado", lambda: app.get_ticket(liaison, 101), request="GET /api/tickets/101", actor="lia", resource=101, expect=200)
            else:
                target = target if transfer else 101
                observe("Anônimo chama ação administrativa", lambda: app.close_ticket(None, target), request=f"POST /api/admin/tickets/{target}/close", resource=target, expect=401)
                observe("Cliente chama API diretamente", lambda: app.close_ticket(other, target), request=f"POST /api/admin/tickets/{target}/close", actor="rafa", resource=target, expect=200 if variant == "before" else 403)
                observe("Administradora executa ação legítima", lambda: app.close_ticket(admin, target), request=f"POST /api/admin/tickets/{target}/close", actor="admin", resource=target, expect=200)
        # Só os probes, que têm horário controlado e entrada redigida, são parte do episódio didático.
        events = [json.loads(r[0]) for r in store.connection.execute("SELECT payload FROM events WHERE json_extract(payload,'$.category')='probe'")]
        for row in events:
            row.update(run_id=identifier, variant=variant, source_ip="192.0.2.50" if "Tentativa controlada" in row["reason"] else "192.0.2.60" if "Outra origem" in row["reason"] else "192.0.2.10")
            probe = next(p for p in observations if p["event_id"] == row["id"])
            row.update(status=probe["status"], request=probe["request"], code_ref="security.py:LoginBudget" if mission == "login" else "helpdesk.py:can_read" if mission == "ownership" else "helpdesk.py:can_close")
        if mission == "login":
            failures = [e for e in events if e["actor"] == "rafa" and e["source_ip"] == "192.0.2.50"]
            if len(failures) >= 3:
                events.append({"id": uuid.uuid4().hex, "run_id": identifier, "timestamp": failures[2]["timestamp"],
                               "observed_at": stamp(), "origin": "derived", "category": "alert", "actor": "rafa", "resource": "login",
                               "decision": "review", "reason": "Três negativas na sequência controlada; sinal de triagem, não prova de invasão.",
                               "correlation_id": failures[2]["correlation_id"], "variant": variant, "status": None,
                               "request": "Regra explícita: 3 negativas / episódio", "source_ip": "192.0.2.50", "code_ref": "scenarios.py:compare"})
        events.sort(key=lambda e: (e["timestamp"], e["origin"] == "derived"))
        variants.append({"id": variant, "events": events, "observations": observations,
                         "operations": count[0], "budget": LIMITS[mission], "initial_data": "Lia/101, Rafael/"+str(707 if transfer else 202)+", Joana/admin; uma empresa fictícia"})
        store.close()
    return {"id": identifier, "mission_id": mission, "mode": "observed_python", "exercise": "transfer" if transfer else "guided",
            "version": VERSION, "scenario_reference": "aurora-helpdesk-v1", "started_at": started, "completed_at": stamp(),
            "code_sha256": code_sha256(), "configuration": {"limit": 5, "window_seconds": 60, "reference_time": BASE_TIME.isoformat(), "variant_transport": "in_process_no_listener"},
            "variants": variants, "checks": checks, "snippets": snippets(mission),
            "limit": "Execução real de funções Python em bancos de memória separados. Sem requisições HTTP nas variantes, contêiner ou isolamento de máquina virtual. Relógio e IPs didáticos; não é incidente real."}
