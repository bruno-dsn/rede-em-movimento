"""Piloto local de continuidade: revisões, escopo e recuperação de arquivos escolhidos."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from .operations_store import canonical, now_stamp, private_bytes, private_directory

SECTORS = {"cartorio", "loja", "escritorio"}
CONTROLS = {"access", "updates", "remote", "offline", "response"}
STATES = {"reviewed", "attention", "critical", "unknown"}
MAX_FILE = 10 * 1024 * 1024
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILES = 1000
MAX_PACKS = 10


def text(value, minimum=1, maximum=200):
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ValueError(f"Texto deve ter de {minimum} a {maximum} caracteres.")
    if any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError("Texto contém caractere de controle.")
    return value.strip()


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Use inteiro de {minimum} a {maximum}.")
    return value


def stamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def safe_name(name):
    if not isinstance(name, str) or len(name) > 500 or "\\" in name or ":" in name:
        raise ValueError("Nome de arquivo não suportado neste piloto.")
    p = PurePosixPath(name)
    if p.is_absolute() or not p.parts or any(x in {"", ".", ".."} for x in name.split("/")):
        raise ValueError("Nome de arquivo fora do escopo.")
    if any(ord(c) < 32 for c in name):
        raise ValueError("Nome contém caractere de controle.")
    return p


def regular_path(path):
    for part in [path, *path.parents]:
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
            raise ValueError("Links e junctions não são permitidos na recuperação.")


def stable_read(before, first, last, after, length, *, windows=None):
    """Compare alterações dentro da mesma API de stat, com identidade comum.

    Windows pode expor tempos com precisão diferente pelo caminho e pelo handle.
    ctime é criação no Windows 3.12; não é indicador de alteração de conteúdo.
    """
    windows = os.name == "nt" if windows is None else windows

    def identity(value):
        return value.st_dev, value.st_ino, value.st_size

    def signature(value):
        return (*identity(value), value.st_mtime_ns, *(() if windows else (value.st_ctime_ns,)))

    return (all(identity(value) == identity(before) for value in (first, last, after))
            and length == first.st_size and length <= MAX_FILE
            and signature(first) == signature(last) and signature(before) == signature(after))


def read_regular(path):
    regular_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
        raise ValueError("Arquivo não regular ou maior que 10 MiB. Nenhuma cópia completa foi registrada.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        first = os.fstat(stream.fileno())
        if not stat.S_ISREG(first.st_mode) or (first.st_dev, first.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("Arquivo mudou durante a abertura.")
        data = stream.read(MAX_FILE + 1)
        last = os.fstat(stream.fileno())
    regular_path(path)
    after = path.lstat()
    if not stable_read(before, first, last, after, len(data)):
        raise ValueError("Arquivo mudou durante a cópia. Tente com a aplicação fechada.")
    return data


class Business:
    def __init__(self, store, clock=None):
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.lock = threading.Lock()
        self.packs = private_directory(store.directory / "recovery-packs")
        self.recovered = private_directory(store.directory / "recovery-tests")
        with store.db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS business_reviews(
              id INTEGER PRIMARY KEY, control TEXT NOT NULL, status TEXT NOT NULL,
              owner TEXT NOT NULL, note TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS recovery_packs(
              id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
              files INTEGER NOT NULL, bytes INTEGER NOT NULL, manifest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS recovery_tests(
              id TEXT PRIMARY KEY, pack_id TEXT NOT NULL REFERENCES recovery_packs(id),
              created_at TEXT NOT NULL, elapsed_seconds REAL NOT NULL, files INTEGER NOT NULL,
              status TEXT NOT NULL, note TEXT NOT NULL);
            """)

    def profile(self, value, actor):
        keys = {"name", "sector", "owner", "rpo_hours", "rto_minutes", "assets"}
        if not isinstance(value, dict) or set(value) != keys or value["sector"] not in SECTORS:
            raise ValueError("Perfil inválido. Escolha cartório, loja ou escritório.")
        if not isinstance(value["assets"], list) or len(value["assets"]) > 100:
            raise ValueError("Inventário: até 100 equipamentos/serviços.")
        assets = []
        for asset in value["assets"]:
            if not isinstance(asset, dict) or set(asset) != {"name", "purpose", "owner"}:
                raise ValueError("Ativo exige nome, finalidade e responsável.")
            assets.append({k: text(v, maximum=120) for k, v in asset.items()})
        profile = {"name": text(value["name"], maximum=100), "sector": value["sector"],
                   "owner": text(value["owner"], maximum=100), "rpo_hours": integer(value["rpo_hours"], 1, 168),
                   "rto_minutes": integer(value["rto_minutes"], 1, 10080), "assets": assets}
        self.store.set("business_profile", profile)
        self.store.audit("business_profile", actor, {"sector": profile["sector"], "assets": len(assets)})
        return self.summary()

    def review(self, control, status, owner, note, actor):
        if control not in CONTROLS or status not in STATES:
            raise ValueError("Controle ou estado inválido.")
        owner, note = text(owner, maximum=100), text(note, minimum=20, maximum=2000)
        with self.store.db() as db:
            db.execute("INSERT INTO business_reviews(control,status,owner,note,actor,created_at) VALUES(?,?,?,?,?,?)",
                       (control, status, owner, note, actor, now_stamp()))
        self.store.audit("business_review", actor, {"control": control, "status": status})
        return self.summary()

    def scope(self):
        roots = self.store.get("config", {}).get("roots", [])
        if not isinstance(roots, list) or not 1 <= len(roots) <= 8:
            raise ValueError("Escolha antes de 1 a 8 pastas com configure --watch. Não há varredura do disco inteiro.")
        result = []
        for value in roots:
            root = Path(value).absolute()
            regular_path(root)
            if not root.is_dir() or root == Path(root.anchor):
                raise ValueError("Pasta escolhida não está disponível ou é a raiz do disco.")
            if root.is_relative_to(self.store.directory) or self.store.directory.is_relative_to(root):
                raise ValueError("Pastas escolhidas não podem conter a pasta de dados do NetGuard.")
            if any(root.is_relative_to(old) or old.is_relative_to(root) for old in result):
                raise ValueError("Pastas escolhidas não podem se sobrepor.")
            result.append(root)
        return result

    def snapshot(self, actor):
        with self.lock:
            roots = self.scope()
            with self.store.db() as db:
                if db.execute("SELECT COUNT(*) FROM recovery_packs").fetchone()[0] >= MAX_PACKS:
                    raise ValueError("Limite de dez cópias atingido. Nenhuma cópia foi removida automaticamente.")
            identifier = uuid.uuid4().hex
            target = self.packs / (identifier + ".zip")
            private_bytes(target, b"")
            files, total, visits = [], 0, 0
            created = now_stamp()
            try:
                with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as archive:
                    for i, root in enumerate(roots):
                        def walk_error(error):
                            raise error
                        for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
                            visits += 1
                            if visits > 2000:
                                raise ValueError("Limite de 2.000 diretórios; reduza o escopo.")
                            for directory_name in dirs:
                                regular_path(Path(directory) / directory_name)
                            for name in sorted(names):
                                if len(files) >= MAX_FILES:
                                    raise ValueError("Limite de 1.000 arquivos; reduza o escopo.")
                                path = Path(directory) / name
                                relative = path.relative_to(root).as_posix()
                                member = f"pasta-{i+1}/" + relative
                                safe_name(member)
                                data = read_regular(path)
                                total += len(data)
                                if total > MAX_TOTAL:
                                    raise ValueError("Limite de 50 MiB por cópia; reduza o escopo.")
                                digest = hashlib.sha256(data).hexdigest()
                                archive.writestr(member, data)
                                files.append({"name": member, "sha256": digest, "bytes": len(data)})
                    if not files:
                        raise ValueError("Nenhum arquivo encontrado nas pastas escolhidas.")
                    manifest = {"format": "netguard-recovery", "version": 1, "created_at": created,
                                "roots": len(roots), "scope_sha256": hashlib.sha256(canonical([str(r) for r in roots]).encode()).hexdigest(),
                                "files": files,
                                "limit": "Cópia local não criptografada; arquivos copiados individualmente, sem snapshot transacional de aplicações."}
                    encoded_manifest = canonical(manifest).encode()
                    if len(encoded_manifest) > 1024 * 1024:
                        raise ValueError("Catálogo de nomes excede 1 MiB; reduza o escopo.")
                    archive.writestr("manifest.json", encoded_manifest)
                digest = hashlib.sha256(target.read_bytes()).hexdigest()
                with self.store.db() as db:
                    db.execute("INSERT INTO recovery_packs VALUES(?,?,?,?,?,?)",
                               (identifier, digest, created, len(files), total, canonical(manifest)))
            except Exception:
                target.unlink(missing_ok=True)
                raise
            self.store.audit("recovery_snapshot", actor, {"id": identifier, "files": len(files), "bytes": total})
            return {"id": identifier, "created_at": created, "files": len(files), "bytes": total,
                    "sha256": digest, "mode": "observed"}

    def restore(self, identifier, actor):
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise ValueError("Identificador de cópia inválido.")
        with self.lock:
            with self.store.db() as db:
                row = db.execute("SELECT * FROM recovery_packs WHERE id=?", (identifier,)).fetchone()
                count = db.execute("SELECT COUNT(*) FROM recovery_tests").fetchone()[0]
            if not row or count >= 20:
                raise ValueError("Cópia desconhecida ou limite de vinte testes atingido.")
            path = self.packs / (identifier + ".zip")
            regular_path(path)
            if not path.is_file() or path.stat().st_size > MAX_TOTAL + 2 * 1024 * 1024:
                self.failure(identifier, actor, "Pacote indisponível ou fora do limite.")
                raise ValueError("Pacote indisponível ou fora do limite.")
            if not hmac.compare_digest(hashlib.sha256(path.read_bytes()).hexdigest(), row["sha256"]):
                self.failure(identifier, actor, "Pacote mudou desde a criação.")
                raise ValueError("O pacote mudou desde a criação. Não foi restaurado.")
            manifest = json.loads(row["manifest"])
            names = [x["name"] for x in manifest["files"]]
            started, test_id = time.monotonic(), uuid.uuid4().hex
            destination = self.recovered / test_id
            try:
                with zipfile.ZipFile(path) as archive:
                    members = archive.infolist()
                    if any(m.compress_type != zipfile.ZIP_STORED or m.file_size > MAX_FILE for m in members):
                        raise ValueError("Formato ou tamanho não corresponde a uma cópia criada por este piloto.")
                    if archive.getinfo("manifest.json").file_size > 1024 * 1024:
                        raise ValueError("Manifesto fora do limite.")
                    if len(members) != len(names) + 1 or len(set(x.filename for x in members)) != len(members):
                        raise ValueError("Pacote tem membros extras ou repetidos.")
                    if set(archive.namelist()) != set(names) | {"manifest.json"}:
                        raise ValueError("Pacote não corresponde ao catálogo.")
                    if archive.read("manifest.json") != canonical(manifest).encode():
                        raise ValueError("Manifesto não corresponde ao catálogo.")
                    private_directory(destination)
                    for item in manifest["files"]:
                        relative = safe_name(item["name"])
                        info = archive.getinfo(item["name"])
                        if info.file_size != item["bytes"] or info.file_size > MAX_FILE or stat.S_ISLNK(info.external_attr >> 16):
                            raise ValueError("Membro inválido.")
                        data = archive.read(item["name"])
                        if hashlib.sha256(data).hexdigest() != item["sha256"]:
                            raise ValueError("Conteúdo diverge do catálogo.")
                        output = destination.joinpath(*relative.parts)
                        private_directory(output.parent)
                        private_bytes(output, data)
                        if hashlib.sha256(read_regular(output)).hexdigest() != item["sha256"]:
                            raise ValueError("Leitura da cópia restaurada diverge.")
                status, note = "verified", "Bytes restaurados em pasta nova e comparados. Ainda exige validação do serviço e do conteúdo por pessoa responsável."
            except Exception:
                with self.store.db() as db:
                    db.execute("INSERT INTO recovery_tests VALUES(?,?,?,?,?,?,?)",
                               (test_id, identifier, now_stamp(), time.monotonic()-started, 0, "failed", "Teste falhou; cópia parcial pode existir somente na pasta de teste."))
                self.store.audit("recovery_failed", actor, {"id": test_id, "pack_id": identifier})
                raise ValueError("Teste de recuperação não concluído; confira o pacote e as permissões.") from None
            elapsed = round(time.monotonic()-started, 6)
            with self.store.db() as db:
                db.execute("INSERT INTO recovery_tests VALUES(?,?,?,?,?,?,?)",
                           (test_id, identifier, now_stamp(), elapsed, len(names), status, note))
            self.store.audit("recovery_verified", actor, {"id": test_id, "pack_id": identifier, "files": len(names)})
            return {"id": test_id, "pack_id": identifier, "files": len(names), "elapsed_seconds": elapsed,
                    "status": status, "destination": str(destination), "note": note}

    def failure(self, identifier, actor, note):
        with self.store.db() as db:
            db.execute("INSERT INTO recovery_tests VALUES(?,?,?,?,?,?,?)",
                       (uuid.uuid4().hex, identifier, now_stamp(), 0, 0, "failed", note))
        self.store.audit("recovery_failed", actor, {"pack_id": identifier})

    def summary(self):
        current = self.clock()
        profile = self.store.get("business_profile", {"name": "Minha empresa", "sector": "escritorio", "owner": "A definir",
                                                    "rpo_hours": 24, "rto_minutes": 240, "assets": []})
        with self.store.db() as db:
            reviews = [dict(r) for r in db.execute("SELECT * FROM business_reviews ORDER BY id DESC LIMIT 200")]
            packs = [dict(r) for r in db.execute("SELECT id,sha256,created_at,files,bytes FROM recovery_packs ORDER BY created_at DESC")]
            catalog = db.execute("SELECT manifest FROM recovery_packs ORDER BY created_at DESC LIMIT 1").fetchone()
            tests = [dict(r) for r in db.execute("SELECT * FROM recovery_tests ORDER BY created_at DESC LIMIT 20")]
            decisions = {r["state"]: r["amount"] for r in db.execute("SELECT COALESCE((SELECT disposition FROM decisions d WHERE d.event_id=e.id ORDER BY id DESC LIMIT 1),'pending') AS state, COUNT(*) AS amount FROM events e GROUP BY state")}
            pending = sum(n for key, n in decisions.items() if key != "recognized")
            incidents = decisions.get("incident", 0)
        controls = []
        for control in sorted(CONTROLS):
            review = next((r for r in reviews if r["control"] == control), None)
            stale = review is not None and not timedelta(0) <= current - stamp(review["created_at"]) <= timedelta(days=30)
            controls.append({"id": control, "status": "unknown" if not review or (stale and review["status"] == "reviewed") else review["status"],
                             "source": "manual", "stale": stale, "review": review})
        latest = packs[0] if packs else None
        roots = self.store.get("config", {}).get("roots", [])
        scope_matches = bool(catalog and json.loads(catalog[0]).get("scope_sha256") == hashlib.sha256(canonical(roots).encode()).hexdigest())
        fresh = bool(latest and scope_matches and timedelta(0) <= current-stamp(latest["created_at"]) <= timedelta(hours=profile["rpo_hours"]))
        verified = next((t for t in tests if latest and t["pack_id"] == latest["id"]), None)
        backup_status = ("unknown" if not latest else "critical" if verified and verified["status"] == "failed"
                         else "attention" if not fresh or not verified else "reviewed")
        summary = self.store.summary()
        heartbeat = summary["heartbeat"]
        active = bool(heartbeat and heartbeat.get("completed_at") and timedelta(0) <= current-stamp(heartbeat["completed_at"]) <= timedelta(seconds=max(120, (summary["settings"].get("interval") or 30)*3)))
        controls += [{"id": "backup", "status": backup_status, "source": "observed", "fresh": fresh, "scope_matches": scope_matches,
                      "note": "Resultado cobre somente arquivos escolhidos, com teste de bytes. Não valida aplicações nem cópia externa/offline."},
                     {"id": "monitor", "status": "reviewed" if active else "unknown", "source": "observed",
                      "note": "Coleta recente observada; fontes e lacunas devem ser conferidas. Não comprova ausência de ameaça."},
                     {"id": "pending", "status": "critical" if incidents else "attention" if pending else "unknown", "source": "observed",
                      "note": f"{pending} eventos com acompanhamento pendente; {incidents} classificados como incidente por operador. Ausência de pendências não prova proteção."}]
        return {"format": "netguard-business", "version": "6.0", "mode": "observed", "generated_at": now_stamp(),
                "profile": profile, "controls": controls, "reviews": reviews, "packs": packs, "tests": tests,
                "operations": summary, "pending_events": pending, "classified_incidents": incidents,
                "limits": {"files": MAX_FILES, "file_bytes": MAX_FILE, "total_bytes": MAX_TOTAL,
                           "packs": MAX_PACKS, "review_valid_days": 30, "commercial_readiness": "piloto local de um equipamento"}}
