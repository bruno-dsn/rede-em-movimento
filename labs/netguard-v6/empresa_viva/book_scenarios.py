"""Seis missões originais, com observações de funções e modelos identificados."""
from __future__ import annotations

import uuid
import sqlite3
from datetime import datetime, timedelta, timezone

from . import VERSION
from .book_models import (BOOK_MISSIONS, Principal, SearchFixture, classify_change, compare_manifests,
                          containment_plan, correlate_access, manifest, permission_allowed, permission_class,
                          recovery_allowed, render_comment, sha256_bytes)
from .store import stamp

BASE_TIME = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)

SNIPPETS = {
    "permissions": {
        "before": "# Modelo DAC: dono / grupo / outros\nmode = 0o644  # rw- r-- r--\n# 'outros' também podem ler",
        "after": "mode = 0o640  # rw- r-- ---\n# dono escreve; grupo autorizado lê; outros não leem\n# ACL, root, diretórios e capacidades não entram neste modelo"},
    "sql": {
        "before": "# Falha intencional no banco descartável\nquery = f\"SELECT ... WHERE owner='{owner}' AND title='{term}'\"",
        "after": "query = 'SELECT ... WHERE owner=? AND title=?'\nrows = db.execute(query, (owner, term))\n# parâmetros são dados, não parte da instrução SQL"},
    "xss": {
        "before": "# Transformação insegura; saída NÃO inserida em HTML ativo\noutput = comment",
        "after": "# Conteúdo textual HTML no Python\noutput = html.escape(comment, quote=True)\n# No navegador: textContent; outros contextos exigem outras defesas"},
    "integrity": {
        "before": "# Uma contagem não mostra quais bytes mudaram\nunchanged = len(before) == len(after)",
        "after": "changes = compare_manifests(before, after)\n# SHA-256, tamanho, criado / alterado / excluído\n# mudança aprovada exige caminho E hash correspondente"},
    "response": {
        "before": "# Decisão insegura do caso fictício\nif alert:\n    erase_records = True\n    reopen_everything = True",
        "after": "plan = containment_plan(asset, authorized=owner_approved)\n# plano apenas; nenhum firewall é alterado\nreopen = all([evidence_preserved, cause_reviewed,\n              credentials_rotated, restore_verified, owner_approved])"},
    "attribution": {
        "before": "# Suposição excessiva\nif outside_work_hours:\n    conclusion = 'invasão confirmada por pessoa X'",
        "after": "finding = correlate_access(event, registered_changes)\n# mesma conta + recurso + correlação\n# pessoa e intenção continuam desconhecidas"},
}


def book_run(mission, transfer, digest):
    if mission not in BOOK_MISSIONS or type(transfer) is not bool:
        raise ValueError("Missão fora do catálogo conhecido.")
    identifier, started = uuid.uuid4().hex, stamp()
    run = {"id": identifier, "mission_id": mission, "mode": "observed_python",
           "exercise": "transfer" if transfer else "guided", "version": VERSION,
           "scenario_reference": "aurora-books-v1", "started_at": started, "code_sha256": digest,
           "configuration": {"reference_time": BASE_TIME.isoformat(), "variant_transport": "in_process_no_listener",
                             "operation_budget": 12, "fixture_only": True, "os_permissions_tested": False,
                             "active_html_executed": False}, "variants": [], "checks": [], "snippets": SNIPPETS[mission],
           "limit": "Funções Python sobre dados fictícios. SQL usa SQLite em memória; HTML é transformado em texto; hashes são de bytes preparados. Permissões, resposta e atribuição são modelos. Sem leitura de arquivos pessoais, shell, tráfego de rede, contêiner ou HTML ativo. Resultados desta missão não são códigos HTTP."}
    for variant in ("before", "after"):
        corrected = variant == "after"
        events, observations = [], []

        def emit(label, actor, resource, data, actual, expected, *, kind="model_decision", decision="review"):
            if len(events) >= 12:
                raise RuntimeError("Orçamento de operações excedido.")
            event_id, correlation = uuid.uuid4().hex, uuid.uuid4().hex
            event = {"id": event_id, "run_id": identifier, "timestamp": (BASE_TIME+timedelta(seconds=len(events)+1)).isoformat(),
                     "observed_at": stamp(), "origin": "observed_python", "category": "probe", "actor": actor,
                     "resource": resource, "decision": decision, "reason": label, "correlation_id": correlation,
                     "variant": variant, "status": None, "result": str(actual), "request": "Fixture local · "+label,
                     "source_ip": "", "code_ref": "book_models.py · "+mission, "evidence_kind": kind}
            events.append(event)
            observations.append({"label": label, "status": None, "request": event["request"], "actor": actor,
                                 "resource": resource, "data": data, "event_id": event_id, "correlation_id": correlation})
            run["checks"].append({"name": f"{variant}: {label}", "expected": expected, "actual": actual,
                                  "passed": type(actual) is type(expected) and actual == expected})

        if mission == "permissions":
            owner, outsider, group = ("lia", "rafa", 2001) if transfer else ("rafa", "lia", 2002)
            principals = {"lia": Principal(1001, frozenset({2001})), "rafa": Principal(1002, frozenset({2002})),
                          "admin": Principal(1003, frozenset({2001, 2002}))}
            mode = 0o640 if corrected else 0o644
            resource = "contratos/renovacao.txt" if transfer else "financeiro/folha.csv"
            for actor, operation, expected in ((outsider, "read", not corrected), (owner, "read", True),
                                               ("admin", "read", True), (owner, "write", True), ("admin", "write", False)):
                allowed = permission_allowed(mode, principals[actor], principals[owner].uid, group, operation)
                cls, _ = permission_class(principals[actor], principals[owner].uid, group)
                emit(f"{actor}: {operation}", actor, resource,
                     {"mode": format(mode, "03o"), "owner": owner, "group_id": group, "selected_class": cls,
                      "operation": operation, "allowed": allowed, "limit": "Modelo de arquivo regular; não testa permissões no SO."},
                     "allowed" if allowed else "denied", "allowed" if expected else "denied", decision="allowed" if allowed else "denied")
        elif mission == "sql":
            fixture = SearchFixture(transfer=transfer)
            try:
                term = "' OR '1'='1" if transfer else "' OR 1=1 --"
                for label, actor, value, expected_count in (("Busca legítima de Lia", "lia", "Acesso", 1),
                                                           ("Entrada altera a lógica da busca", "lia", term, 0 if corrected else 3),
                                                           ("Busca legítima de Rafael", "rafa", "Financeiro", 1),
                                                           ("Apóstrofo tratado como dado", "lia", "D'Ávila", 1)):
                    try:
                        rows = fixture.search(actor, value, corrected=corrected)
                    except sqlite3.OperationalError:
                        if corrected or label != "Apóstrofo tratado como dado":
                            raise
                        emit(label, actor, "items", {"input": value, "query_error": "Entrada quebrou a consulta concatenada."},
                             "query_rejected", "query_rejected", kind="sqlite_result", decision="denied")
                        continue
                    emit(label, actor, "items", {"input": value, "rows": rows, "parameters_bound": corrected,
                                               "foreign_records": sum(row["owner"] != actor for row in rows)},
                         len(rows), expected_count, kind="sqlite_result", decision="review" if any(r["owner"] != actor for r in rows) else "allowed")
            finally:
                fixture.close()
        elif mission == "xss":
            marker = '<svg onload="alert(\'LAB-FICTICIO\')"></svg>' if transfer else '<img src=x onerror="alert(\'LAB-FICTICIO\')">'
            for label, value in (("Comentário legítimo", "Manutenção concluída."), ("Marcador HTML controlado", marker),
                                 ("Texto com símbolos", "A & B < orçamento > ontem")):
                output = render_comment(value, corrected=corrected)
                text_only = output == render_comment(value, corrected=True)
                expected = True if corrected or label == "Comentário legítimo" else False
                emit(label, "lia", "comment", {"input": value, "output": output, "text_only": text_only,
                                               "active_html_executed": False, "context": "Conteúdo textual HTML"},
                     text_only, expected, kind="html_transformation", decision="allowed" if text_only else "review")
        elif mission == "integrity":
            before = {"financeiro.csv": b"total,100\n", "backup.txt": b"backup-v1\n", "config.txt": b"mode=old\n"}
            after = {"financeiro.csv": b"total,900\n", "backup.txt": b"backup-v2\n", "nota.txt": b"novo registro ficticio\n"}
            if transfer:
                after["backup.txt"] = b"backup-X2\n"  # mesmo nome/tamanho, bytes diferentes da mudança aprovada
            approvals = {"backup.txt": sha256_bytes(b"backup-v2\n")}
            old, new = manifest(before), manifest(after)
            emit("Mesmo número de arquivos", "admin", "manifest", {"before_count": len(old), "after_count": len(new),
                 "limit": "Contagem igual não prova conteúdo igual."}, len(old) == len(new), True, kind="synthetic_bytes")
            if not corrected:
                emit("Conclusão baseada só na contagem", "admin", "manifest", {"conclusion": "Nada mudou; decisão insegura."},
                     "no_changes", "no_changes", kind="model_decision")
            else:
                for change in compare_manifests(old, new):
                    classification = classify_change(change, approvals)
                    expected = "approved_change" if change["path"] == "backup.txt" and not transfer else "needs_review"
                    emit("Alteração: "+change["kind"], "admin", change["path"],
                         {**change, "classification": classification, "approved_sha256": approvals.get(change["path"]),
                          "limit": "Hash diferente comprova bytes diferentes, não malware ou autoria."},
                         classification, expected, kind="synthetic_bytes")
                emit("Cópia preparada preserva os bytes", "admin", "evidence-copy",
                     {"source_sha256": sha256_bytes(after["financeiro.csv"]), "copy_sha256": sha256_bytes(bytes(after["financeiro.csv"])),
                      "limit": "Cópia em memória; não é backup externo nem cadeia de custódia."},
                     sha256_bytes(after["financeiro.csv"]) == sha256_bytes(bytes(after["financeiro.csv"])), True, kind="synthetic_bytes")
        elif mission == "response":
            asset = "helpdesk-server" if transfer else "finance-server"
            if not corrected:
                emit("Alerta tratado como certeza", "admin", asset, {"evidence_preserved": False, "impact": "Interromper toda a empresa sem validar o alcance."},
                     "erase_and_reopen", "erase_and_reopen")
            else:
                pending = containment_plan(asset, authorized=False)
                emit("Responsável ainda não autorizou", "admin", asset, pending, pending["state"], "pending_authorization")
                plan = containment_plan(asset, authorized=True)
                emit("Plano limitado ao ativo afetado", "admin", asset, plan, plan["commands_executed"], 0)
                readiness = dict(evidence_preserved=True, cause_reviewed=True, credentials_rotated=True, restore_verified=False, owner_approved=True)
                emit("Backup ainda não teve restauração conferida", "admin", asset, readiness,
                     recovery_allowed(**readiness), False, decision="denied")
                readiness["restore_verified"] = True
                if transfer:
                    readiness["owner_approved"] = False
                ready = recovery_allowed(**readiness)
                emit("Conferência dos critérios de retorno", "admin", asset, readiness,
                     ready, not transfer, decision="allowed" if ready else "denied")
        elif mission == "attribution":
            events_fixture = [
                {"account": "admin", "resource": "backup", "correlation_id": "job-42", "source_ip": "192.0.2.50", "outside_work_hours": True},
                {"account": "rafa", "resource": "financeiro.csv", "correlation_id": "access-17", "source_ip": "192.0.2.50", "outside_work_hours": True}]
            changes = [{"account": "admin", "resource": "backup", "correlation_id": "job-42"}]
            if transfer:
                events_fixture[1]["outside_work_hours"] = False
                events_fixture[1]["source_ip"] = "192.0.2.60"
            for event in events_fixture:
                data = correlate_access(event, changes) if corrected else {
                    "classification": "person_accused" if event["outside_work_hours"] else "ignored",
                    "person": "Suposição sem evidência", "limit": "Regra intencionalmente inadequada."}
                expected = ("documented_maintenance" if event["resource"] == "backup" else "needs_review") if corrected else (
                    "person_accused" if event["outside_work_hours"] else "ignored")
                emit("Acesso com contexto: "+event["resource"], event["account"], event["resource"], {"record": event, "finding": data},
                     data["classification"], expected, decision="allowed" if corrected and expected == "documented_maintenance" else "review")
        run["variants"].append({"id": variant, "events": events, "observations": observations,
                                "operations": len(events), "budget": 12,
                                "initial_data": "Fixtures finitas da Aurora; estados antes/depois independentes, sem arquivos pessoais."})
    run["completed_at"] = stamp()
    return run
