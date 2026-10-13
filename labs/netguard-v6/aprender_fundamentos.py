"""Exercícios autorais com fixtures fixas. Não consulta rede, executa shell ou altera arquivos."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from dataclasses import dataclass

EVENTS = [
    {"time": "2026-10-12T12:00:00Z", "account": "aluno", "status": "failure", "ip": "192.0.2.10"},
    {"time": "2026-10-12T12:00:20Z", "account": "aluno", "status": "failure", "ip": "192.0.2.10"},
    {"time": "2026-10-12T12:01:00Z", "account": "aluno", "status": "success", "ip": "192.0.2.10"},
]


@dataclass(frozen=True)
class Asset:
    name: str
    purpose: str
    owner: str

    def __post_init__(self):
        if any(not isinstance(x, str) or not x.strip() for x in (self.name, self.purpose, self.owner)):
            raise ValueError("Ativo exige nome, finalidade e responsável.")

    def describe(self):
        return f"{self.name}: {self.purpose}. Responsável: {self.owner}."


def count_events(events):
    result = {"failure": 0, "success": 0}
    for event in events:
        if set(event) != {"time", "account", "status", "ip"} or event["status"] not in result:
            raise ValueError("Fixture com campos ou status inválidos.")
        ipaddress.ip_address(event["ip"])
        result[event["status"]] += 1
    return result


def exercise(kind):
    if kind == "logs":
        return {"mode": "fixed_fixture", "source": EVENTS, "counts": count_events(EVENTS),
                "question": "Duas falhas e um sucesso provam invasão? Explique quais evidências faltam.",
                "limit": "Contagem não comprova causa, pessoa ou legitimidade. IPs são de documentação."}
    if kind == "hash":
        original, changed = b"documento ficticio v1", b"documento ficticio v2"
        return {"mode": "fixed_fixture", "original_sha256": hashlib.sha256(original).hexdigest(),
                "changed_sha256": hashlib.sha256(changed).hexdigest(), "same": original == changed,
                "question": "Hash diferente identifica quem mudou o conteúdo? E permite recuperar v1?",
                "limit": "Comparação de bytes preparados em memória; não é backup."}
    if kind == "classes":
        asset = Asset("PC de teste", "Produzir documentos fictícios", "Aluna fictícia")
        return {"mode": "fixed_fixture", "description": asset.describe(),
                "question": "Tente criar uma instância com finalidade vazia no código: qual regra deve ser preservada?"}
    if kind == "ip":
        values = []
        for value in ("192.0.2.10", "2001:db8::10", "999.1.2.3"):
            try:
                address = ipaddress.ip_address(value)
                values.append({"input": value, "valid": True, "version": address.version})
            except ValueError:
                values.append({"input": value, "valid": False})
        return {"mode": "fixed_fixture", "results": values, "question": "Por que apenas contar pontos não valida IPv4?"}
    raise ValueError("Exercício desconhecido.")


def main():
    parser = argparse.ArgumentParser(description="Fundamentos NetGuard · fixtures locais e explicações")
    parser.add_argument("exercise", choices=["logs", "hash", "classes", "ip"])
    args = parser.parse_args()
    print(json.dumps(exercise(args.exercise), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
