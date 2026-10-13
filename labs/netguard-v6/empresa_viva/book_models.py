"""Operações finitas sobre fixtures. Não lê arquivos, executa shell ou abre rede.

Os controles intencionais de SQL/HTML só são comparados dentro do executor.
Permissões, resposta e atribuição são modelos, não testes do SO ou do navegador.
"""
from __future__ import annotations

import hashlib
import html
import sqlite3
from dataclasses import dataclass

BOOK_MISSIONS = ("permissions", "sql", "xss", "integrity", "response", "attribution")


@dataclass(frozen=True)
class Principal:
    uid: int
    groups: frozenset[int]


def permission_class(principal, owner, group):
    """A classe selecionada não recorre aos bits de outras classes."""
    if principal.uid == owner:
        return "owner", 6
    if group in principal.groups:
        return "group", 3
    return "others", 0


def permission_allowed(mode, principal, owner, group, operation="read"):
    if type(mode) is not int or not 0 <= mode <= 0o777:
        raise ValueError("Use apenas os nove bits de permissões do modelo.")
    if operation not in {"read", "write", "execute"}:
        raise ValueError("Operação desconhecida.")
    _, shift = permission_class(principal, owner, group)
    bit = {"read": 4, "write": 2, "execute": 1}[operation]
    return bool(((mode >> shift) & 7) & bit)


class SearchFixture:
    """Um SELECT fixo em SQLite descartável. Nenhum SQL recebido pela API."""
    def __init__(self, *, transfer=False):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE items(id INTEGER, owner TEXT, title TEXT)")
        self.rows = [(101, "lia", "Acesso"), (707 if transfer else 202, "rafa", "Financeiro"),
                     (303, "lia", "D'Ávila")]
        self.db.executemany("INSERT INTO items VALUES(?,?,?)", self.rows)
        # Mesmo a demonstração intencional não permite attach, extensão, escrita ou DDL.
        self.db.set_authorizer(lambda action, table, *unused: sqlite3.SQLITE_OK if (
            action == sqlite3.SQLITE_SELECT or action == sqlite3.SQLITE_READ and table == "items") else sqlite3.SQLITE_DENY)
        self.db.set_progress_handler(lambda: 1, 10_000)

    def search(self, owner, term, *, corrected=True):
        if owner not in {"lia", "rafa"} or not isinstance(term, str) or len(term) > 80:
            raise ValueError("Entrada fora do exercício.")
        if corrected:
            query, values = "SELECT id,owner,title FROM items WHERE owner=? AND title=?", (owner, term)
        else:
            # Falha intencional, unicamente no banco :memory: deste exercício.
            query, values = f"SELECT id,owner,title FROM items WHERE owner='{owner}' AND title='{term}'", ()
        return [dict(row) for row in self.db.execute(query, values).fetchall()]

    def close(self):
        self.db.close()


def render_comment(text, *, corrected=True):
    if not isinstance(text, str) or len(text) > 512:
        raise ValueError("Comentário fora do exercício.")
    # Saída para conteúdo textual HTML. Não é encoder para JS, CSS ou URL.
    return html.escape(text, quote=True) if corrected else text


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def manifest(files):
    return {name: {"sha256": sha256_bytes(value), "size": len(value)} for name, value in files.items()}


def compare_manifests(before, after):
    changes = []
    for name in sorted(set(before) | set(after)):
        kind = "created" if name not in before else "deleted" if name not in after else "modified"
        if kind == "modified" and before[name] == after[name]:
            continue
        changes.append({"path": name, "kind": kind, "before": before.get(name), "after": after.get(name)})
    return changes


def classify_change(change, approvals):
    """A autorização precisa corresponder ao caminho E ao conteúdo aprovado."""
    expected = approvals.get(change["path"])
    observed = change["after"]
    if expected and observed and expected == observed["sha256"] and change["kind"] in {"created", "modified"}:
        return "approved_change"
    return "needs_review"


def containment_plan(asset, *, authorized, preserve_internal=True):
    if asset not in {"finance-server", "helpdesk-server"} or type(authorized) is not bool or type(preserve_internal) is not bool:
        raise ValueError("Plano fora dos ativos fictícios.")
    if not authorized:
        return {"state": "pending_authorization", "asset": asset, "commands_executed": 0,
                "next": "Preservar evidências disponíveis e solicitar decisão ao responsável."}
    return {"state": "planned_only", "asset": asset, "commands_executed": 0,
            "internet": "block_for_affected_asset", "internal_network": "management_path_only" if preserve_internal else "isolated",
            "next": "Restringir também caminhos internos desnecessários; corte de internet não remove malware."}


def recovery_allowed(*, evidence_preserved, cause_reviewed, credentials_rotated, restore_verified, owner_approved):
    values = (evidence_preserved, cause_reviewed, credentials_rotated, restore_verified, owner_approved)
    if any(type(v) is not bool for v in values):
        raise ValueError("Critérios de recuperação precisam ser booleanos.")
    return all(values)


def correlate_access(event, changes):
    """IP/horário são contexto, não identidade pessoal nem autorização."""
    approved = next((change for change in changes if change["account"] == event["account"]
                     and change["resource"] == event["resource"] and change["correlation_id"] == event["correlation_id"]), None)
    return {"classification": "documented_maintenance" if approved else "needs_review",
            "person": "unknown", "source_ip": event["source_ip"], "account": event["account"],
            "basis": "Conta, recurso e correlação com mudança registrada." if approved else "Não há mudança correspondente neste conjunto de registros.",
            "limit": "Registro de conta não comprova quem a usou; ausência de mudança não comprova intenção."}
