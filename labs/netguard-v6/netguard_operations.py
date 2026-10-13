"""Entrada do console operacional local. Requer Python 3.12+; somente stdlib."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from netguard.operations_containment import Containment  # noqa: E402
from netguard.operations_monitor import Monitor  # noqa: E402
from netguard.operations_server import OperationsServer  # noqa: E402
from netguard.operations_store import Store, clean  # noqa: E402


def configuration(store, args):
    current = {"roots": [], "interval": 30, "snapshot_files": False, "auto_backup": True,
               "business_start": 8, "business_end": 18, **store.get("config", {})}
    if args.clear_watch:
        current["roots"] = []
    if args.watch:
        roots = []
        for value in args.watch:
            supplied = Path(value).expanduser().absolute()
            for part in [supplied, *supplied.parents]:
                if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
                    raise ValueError("Pastas observadas não podem atravessar links/junctions.")
            path = supplied.resolve()
            if not path.is_dir() or path == Path(path.anchor):
                raise ValueError("Escolha uma pasta existente, sem selecionar a raiz do disco.")
            if path.is_relative_to(store.directory) or store.directory.is_relative_to(path):
                raise ValueError("A pasta observada não pode conter, nem estar dentro, da pasta de evidências.")
            if any(path.is_relative_to(old) or Path(old).is_relative_to(path) for old in roots):
                raise ValueError("Não selecione pastas sobrepostas.")
            roots.append(str(path))
        if len(roots) > 8:
            raise ValueError("Selecione no máximo oito pastas.")
        current["roots"] = roots
    for name in ("interval", "snapshot_files", "auto_backup", "business_start", "business_end"):
        value = getattr(args, name, None)
        if value is not None:
            current[name] = value
    if not 10 <= current["interval"] <= 3600 or not 0 <= current["business_start"] < current["business_end"] <= 24:
        raise ValueError("Intervalo: 10–3600 segundos. Expediente: início menor que fim, de 0 a 24.")
    store.set("config", current)
    store.audit("configuration_changed", "local-cli", {"roots": len(current["roots"]), "interval": current["interval"],
                                                        "snapshot_files": current["snapshot_files"]})
    return current


class ProcessLock:
    """Um monitor por banco; o lock do SO é liberado mesmo se o processo morrer."""
    def __init__(self, path):
        self.path = path
        self.stream = None

    def __enter__(self):
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.stream = os.fdopen(fd, "r+b", buffering=0)
        if os.name == "nt":
            import msvcrt
            if self.path.stat().st_size == 0:
                self.stream.write(b"0")
                self.stream.seek(0)
            try:
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                self.stream.close()
                raise ValueError("Já existe um monitor usando esta pasta de dados.") from None
        else:
            import fcntl
            try:
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                self.stream.close()
                raise ValueError("Já existe um monitor usando esta pasta de dados.") from None
        return self

    def __exit__(self, *_):
        self.stream.close()


def parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--directory", default=argparse.SUPPRESS, help="Pasta privada de estado; padrão: ~/NetGuard-Operations")
    result = argparse.ArgumentParser(description="NetGuard Operações · console local", parents=[common])
    commands = result.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", parents=[common], help="Criar operador; senha solicitada sem eco")
    init.add_argument("--username", default="operador")
    init.add_argument("--alias", default="Meu computador")
    config = commands.add_parser("configure", parents=[common], help="Selecionar pastas e cadência de coleta")
    config.add_argument("--watch", action="append", help="Pasta autorizada; repita para outras")
    config.add_argument("--clear-watch", action="store_true")
    config.add_argument("--interval", type=int)
    config.add_argument("--snapshot-files", action=argparse.BooleanOptionalAction, default=None)
    config.add_argument("--auto-backup", action=argparse.BooleanOptionalAction, default=None)
    config.add_argument("--business-start", type=int)
    config.add_argument("--business-end", type=int)
    serve = commands.add_parser("serve", parents=[common], help="Manter monitor e console ativos enquanto o processo executar")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--enable-containment", action="store_true", help="Permitir ações manuais Windows; exige elevação do processo")
    for name in ("once", "backup", "integrity"):
        commands.add_parser(name, parents=[common])
    password = commands.add_parser("password", parents=[common])
    password.add_argument("--username", default="operador")
    release = commands.add_parser("release", parents=[common], help="Recuperação local: remover somente regras de um plano conhecido")
    release.add_argument("--id", required=True)
    release.add_argument("--username", default="operador")
    release.add_argument("--note", required=True)
    return result


def main(argv=None):
    if sys.version_info < (3, 12):
        print("Requer Python 3.12 ou superior.", file=sys.stderr)
        return 1
    args = parser().parse_args(argv)
    try:
        store = Store(getattr(args, "directory", Path.home()/"NetGuard-Operations"))
        if args.command == "init":
            if store.has_user():
                raise ValueError("Já existe um operador. Use serve ou password.")
            password = getpass.getpass("Senha (12–256 caracteres): ")
            repeat = getpass.getpass("Repita a senha: ")
            if password != repeat:
                raise ValueError("As senhas são diferentes.")
            store.init_user(args.username, password)
            device = store.get("device")
            device["alias"] = clean(args.alias, 100) or "Meu computador"
            store.set("device", device)
            print("Operador criado. Selecione pastas com configure e inicie com serve.")
        elif args.command == "configure":
            if not store.has_user():
                raise ValueError("Crie primeiro o operador com init.")
            config = configuration(store, args)
            print(json.dumps({"watch_roots": len(config["roots"]), "interval_seconds": config["interval"],
                              "snapshot_files": config["snapshot_files"]}, ensure_ascii=False))
        elif args.command == "serve":
            if not store.has_user():
                raise ValueError("Crie primeiro o operador com init.")
            if not 1024 <= args.port <= 65535:
                raise ValueError("Porta precisa estar entre 1024 e 65535.")
            with ProcessLock(store.directory/"monitor.lock"):
                server = OperationsServer(store, args.port, enable_containment=args.enable_containment)
                print(f"NetGuard Empresas: http://127.0.0.1:{server.server_port}/index.html", flush=True)
                print("Monitor ativo enquanto este processo e o computador estiverem ligados. Ctrl+C encerra a coleta.", flush=True)
                if args.enable_containment:
                    print("Contenção habilitada somente para ações manuais Windows. Regras permanecem até liberação explícita.", flush=True)
                server.monitor.start()
                try:
                    server.serve_forever(poll_interval=0.5)
                except KeyboardInterrupt:
                    pass
                finally:
                    server.monitor.stop()
                    server.server_close()
        elif args.command == "once":
            if not store.has_user():
                raise ValueError("Crie primeiro o operador com init.")
            with ProcessLock(store.directory/"monitor.lock"):
                Monitor(store).cycle()
            print(json.dumps({"counts": store.summary()["counts"], "coverage": store.summary()["coverage"]}, ensure_ascii=False))
        elif args.command == "backup":
            print(json.dumps(store.backup("local-cli"), ensure_ascii=False))
        elif args.command == "integrity":
            print(json.dumps(store.verify_chain(), ensure_ascii=False))
        elif args.command == "password":
            current = getpass.getpass("Senha atual: ")
            new = getpass.getpass("Nova senha: ")
            if new != getpass.getpass("Repita a nova senha: "):
                raise ValueError("As senhas são diferentes.")
            store.change_password(args.username, current, new)
            print("Senha alterada. Sessões existentes serão recusadas na próxima requisição.")
        elif args.command == "release":
            result = Containment(store, enabled=True).release(args.id, args.username, getpass.getpass("Senha do operador: "), args.note)
            print(json.dumps(result, ensure_ascii=False))
        return 0
    except (ValueError, OSError) as ex:
        print("NetGuard: "+str(ex), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
