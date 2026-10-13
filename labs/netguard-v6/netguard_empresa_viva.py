"""Entrada do NetGuard Empresa Viva. Runtime sem dependências externas, Python 3.12+."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import warnings
from pathlib import Path

from empresa_viva.reports import authentication_csv, evidence_json
from empresa_viva.scenarios import MISSION_IDS, catalog, compare
from empresa_viva.server import Server
from empresa_viva.store import Store, private_directory


class Lease:
    def __init__(self, directory):
        path = directory/"empresa-viva.lock"
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise ValueError("O arquivo de exclusão do laboratório não pode ser um link.")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.file = os.fdopen(fd, "r+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                self.file.write(b"0")
                self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise ValueError("Outro processo usa esta pasta. Encerre-o antes de continuar.") from None

    def close(self):
        self.file.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="NetGuard · Empresa Viva, com dados fictícios e laboratório em memória.")
    parser.add_argument("--data-dir", type=Path, default=Path.home()/"NetGuard-Empresa-Viva")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Criar três contas com senhas solicitadas no terminal, sem senha padrão.")
    serve = commands.add_parser("serve", help="Portal corrigido em 127.0.0.1; Ctrl+C encerra.")
    serve.add_argument("--port", type=int, default=8790)
    run = commands.add_parser("run", help="Executar um episódio fixo em memória; nenhuma conexão externa.")
    run.add_argument("--mission", choices=MISSION_IDS, required=True)
    run.add_argument("--transfer", action="store_true")
    run.add_argument("--output", type=Path, default=Path("reports/empresa-viva"))
    verify = commands.add_parser("verify", help="Comparar as nove missões e seus casos de transferência.")
    verify.add_argument("--output", type=Path, default=Path("reports/empresa-viva"))
    args = parser.parse_args(argv)
    if sys.version_info < (3, 12):
        parser.error("Requer Python 3.12+.")
    lease = store = server = None
    try:
        catalog()
        if args.command in {"run", "verify"}:
            output = private_directory(args.output)
            runs = [compare(args.mission, transfer=args.transfer)] if args.command == "run" else [
                compare(mission, transfer=transfer) for mission in MISSION_IDS for transfer in (False, True)]
            for result in runs:
                name = "execucao-"+result["id"]
                file = output/(name+".json")
                file.write_text(evidence_json(result), encoding="utf-8")
                if result["mission_id"] == "login":
                    (output/(name+"-autenticacao.csv")).write_text(authentication_csv(result), encoding="utf-8")
                if os.name != "nt":
                    file.chmod(0o600)
            summary = {"product": "netguard-empresa-viva", "origin": "observed_python", "runs": len(runs),
                       "checks": sum(len(r["checks"]) for r in runs), "passed": sum(c["passed"] for r in runs for c in r["checks"]),
                       "code_sha256": runs[0]["code_sha256"], "network_tests": "Nenhuma variante exposta em HTTP; execução em memória.",
                       "browser_qa": "Não executada por este comando.", "output": str(output)}
            (output/"verificacao.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(summary, ensure_ascii=False))
            return 0 if summary["checks"] == summary["passed"] else 1
        directory = private_directory(args.data_dir)
        lease = Lease(directory)
        store = Store(directory)
        if args.command == "init":
            if store.initialized():
                raise ValueError("Dados já inicializados. As contas existentes foram preservadas.")
            print("Contas fictícias: lia, rafa e admin. As senhas não são exibidas nem registradas.")
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                try:
                    passwords = {name: getpass.getpass(f"Senha própria para {name} (12–256 caracteres): ") for name in ("lia", "rafa", "admin")}
                except getpass.GetPassWarning:
                    raise ValueError("Use um terminal interativo com entrada de senha protegida; nenhuma conta foi criada.") from None
            store.initialize(passwords)
            passwords.clear()
            print("Contas e chamados fictícios criados. Execute: python3 netguard_empresa_viva.py serve")
        else:
            if not store.initialized():
                raise ValueError("Execute init primeiro; não há senha padrão.")
            if not 1024 <= args.port <= 65535:
                raise ValueError("Escolha uma porta entre 1024 e 65535.")
            server = Server(store, args.port)
            print(f"Portal local corrigido: {server.origin}/ · Ctrl+C encerra. Variantes falhas só em memória.")
            server.serve_forever()
        return 0
    except KeyboardInterrupt:
        print("\nNetGuard Empresa Viva encerrado. Evidências locais preservadas.")
        return 0
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    finally:
        if server:
            server.server_close()
        if store:
            store.close()
        if lease:
            lease.close()


if __name__ == "__main__":
    raise SystemExit(main())
