"""Fontes limitadas e explícitas: arquivos escolhidos, TCP e autenticação local."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import stat
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .checkup import Unavailable, make_report, run_command
from .operations_store import MAX_COPY, Store, clean, now_stamp

MAX_FILES = 5_000
MAX_FILE = 10_485_760
SCAN_BUDGET = 104_857_600
WIN_FIELDS = ("TargetUserName", "SubjectUserName", "IpAddress", "IpPort", "LogonType",
              "TargetLogonId", "SubjectLogonId", "ObjectName", "AccessMask", "ObjectType", "MemberName")
WIN_NETWORK = "@(Get-NetTCPConnection -State Established | Select-Object -First 501 LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess) | ConvertTo-Json -Compress"


def powershell(script, runner=run_command):
    exe = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not exe:
        raise Unavailable("PowerShell indisponível.")
    prefix = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();"
    encoded = base64.b64encode((prefix+script).encode("utf-16-le")).decode()
    return json.loads(runner([exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]) or "null")


def windows_auth_script(since):
    since = datetime.fromisoformat(since.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    fields = ",".join("'"+name+"'" for name in WIN_FIELDS)
    return ("try { $events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4672,4720,4732,1102,4663;"
            f"StartTime=[datetime]::Parse('{since}').ToLocalTime()" + "} -MaxEvents 201 -ErrorAction Stop);"
            "$out=@($events | ForEach-Object { $ev=$_; $xml=[xml]$ev.ToXml(); $d=@{};"
            f"foreach($n in $xml.Event.EventData.Data) {{ if(@({fields}) -contains [string]$n.Name) {{ $d[[string]$n.Name]=[string]$n.'#text' }} }};"
            "@{id=[int]$ev.Id;record=[long]$ev.RecordId;time=$ev.TimeCreated.ToUniversalTime().ToString('o');data=$d} });"
            "@{events=$out;bounded=($events.Count -ge 201)} | ConvertTo-Json -Depth 6 -Compress"
            "} catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { @{events=@();bounded=$false} | ConvertTo-Json -Compress } else { throw } }")


def valid_peer(value):
    try:
        address = ipaddress.ip_address(str(value).split("%")[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return str(address) if not address.is_unspecified else ""
    except ValueError:
        return ""


def peer_scope(value):
    if not value:
        return "não informado"
    address = ipaddress.ip_address(value)
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link local"
    return "faixa privada/especial" if not address.is_global else "faixa pública"


def after_hours(stamp, config):
    local = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone()
    return local.weekday() >= 5 or not config.get("business_start", 8) <= local.hour < config.get("business_end", 18)


def read_file(path, copy=False):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE or getattr(before, "st_file_attributes", 0) & 1024:
        raise ValueError("Arquivo não regular, redirecionado ou maior que 10 MiB.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    digest, parts = hashlib.sha256(), []
    with os.fdopen(fd, "rb") as stream:
        initial = os.fstat(stream.fileno())
        if not stat.S_ISREG(initial.st_mode) or initial.st_ino != before.st_ino or initial.st_dev != before.st_dev:
            raise ValueError("Arquivo mudou durante abertura.")
        total = 0
        while chunk := stream.read(65_536):
            total += len(chunk)
            if total > MAX_FILE:
                raise ValueError("Arquivo cresceu além do limite.")
            digest.update(chunk)
            if copy and before.st_size <= MAX_COPY:
                parts.append(chunk)
        final = os.fstat(stream.fileno())
        if (initial.st_size, initial.st_mtime_ns, initial.st_ino) != (final.st_size, final.st_mtime_ns, final.st_ino):
            raise ValueError("Arquivo em alteração; será tentado no próximo ciclo.")
    return digest.hexdigest(), total, b"".join(parts) if copy and total <= MAX_COPY else None


class Monitor:
    def __init__(self, store: Store, *, system=None, runner=run_command):
        self.store = store
        self.system = system or platform.system()
        self.runner = runner
        self.stop_event = threading.Event()
        self.cycle_lock = threading.Lock()
        self.thread = None

    def scan_files(self):
        config = self.store.get("config", {})
        roots = config.get("roots", [])
        if not roots:
            self.store.coverage("files", "unavailable", "Escolha pastas com configure --watch. Nenhum disco inteiro é observado.")
            return
        used_bytes, total_files, incomplete = 0, 0, False
        for index, root_string in enumerate(roots):
            root = Path(root_string)
            root_id = hashlib.sha256(str(root).encode()).hexdigest()[:32]
            label = f"pasta-{index+1}"
            if not root.is_dir() or root.is_symlink() or getattr(root, "is_junction", lambda: False)():
                incomplete = True
                continue
            seen, changed, complete = {}, [], True
            baseline = self.store.get("baseline-"+root_id, False)
            with self.store.db() as db:
                previous = {r["path"]: dict(r) for r in db.execute("SELECT * FROM files WHERE root=?", (root_id,))}
            def walk_error(_):
                nonlocal complete
                complete = False
            for directory, subdirs, filenames in os.walk(root, followlinks=False, onerror=walk_error):
                subdirs[:] = [name for name in sorted(subdirs) if not (Path(directory)/name).is_symlink()
                              and not getattr(Path(directory)/name, "is_junction", lambda: False)()]
                for name in sorted(filenames):
                    path = Path(directory)/name
                    if path.is_symlink():
                        complete = False
                        continue
                    if total_files >= MAX_FILES or used_bytes >= SCAN_BUDGET:
                        complete = False
                        break
                    try:
                        if not path.resolve().is_relative_to(root.resolve()):
                            raise ValueError("Caminho fora da pasta escolhida.")
                        size = path.stat().st_size
                        if used_bytes+size > SCAN_BUDGET:
                            raise ValueError("Orçamento de leitura excedido.")
                        digest, size, data = read_file(path, bool(config.get("snapshot_files")))
                        total_files += 1
                        used_bytes += size
                        relative = path.relative_to(root).as_posix()
                        seen[relative] = {"digest": digest, "size": size}
                        old = previous.get(relative)
                        if not baseline and not old:
                            continue  # inventário inicial, sem chamar arquivos existentes de invasão
                        if old and old["digest"] == digest:
                            continue
                        kind = "file_changed" if old else "file_appeared"
                        meta = {"root": label, "sha256": digest, "previous_sha256": old["digest"] if old else "",
                                "size": size, "previous_size": old["size"] if old else None,
                                "copy_status": "não habilitada", "baseline_complete_before": baseline,
                                "limit": "Hash detecta conteúdo diferente; não revela quem escreveu, de onde veio ou se houve cópia para fora."}
                        if config.get("snapshot_files"):
                            if data is None:
                                meta["copy_status"] = "arquivo maior que 1 MiB"
                            else:
                                try:
                                    meta["copy_id"] = self.store.capture(data, digest)
                                    meta["copy_status"] = "cópia preservada"
                                except (OSError, ValueError):
                                    meta["copy_status"] = "cópia não preservada: limite ou erro de armazenamento"
                        code = path.suffix.lower() in {".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".py", ".sh", ".vbs"}
                        title = "Conteúdo de arquivo mudou" if old else "Arquivo passou a ser observado"
                        self.store.add_event(kind, title, "file-hash", severity="attention" if code else "info",
                                             path=label+"/"+relative, metadata=meta)
                        changed.append(relative)
                    except (OSError, ValueError):
                        complete = False
                if not complete and (total_files >= MAX_FILES or used_bytes >= SCAN_BUDGET):
                    break
            if complete:
                for missing in previous.keys()-seen.keys():
                    self.store.add_event("file_missing", "Arquivo deixou de ser observado", "file-hash",
                                         path=label+"/"+missing,
                                         metadata={"sha256": previous[missing]["digest"], "size": previous[missing]["size"],
                                                   "limit": "Ausência nesta pasta; pode ter sido movido ou excluído. Não identifica o responsável."})
            with self.store.db() as db:
                for path, data in seen.items():
                    db.execute("INSERT OR REPLACE INTO files VALUES(?,?,?,?)", (root_id, path, data["digest"], data["size"]))
                if complete:
                    for missing in previous.keys()-seen.keys():
                        db.execute("DELETE FROM files WHERE root=? AND path=?", (root_id, missing))
            if not baseline:
                self.store.add_event("baseline", "Linha de base da pasta registrada", "file-hash",
                                     metadata={"root": label, "files": len(seen), "complete": complete,
                                               "limit": "Inventário inicial observado, sem atestado de conteúdo seguro."})
            self.store.set("baseline-"+root_id, complete)
            incomplete |= not complete
        self.store.coverage("files", "partial" if incomplete else "observed",
                            f"{total_files} arquivos lidos neste ciclo; até 5.000 e 100 MiB/ciclo, 10 MiB/arquivo. "
                            "Polling pode perder criação/exclusão entre ciclos; links/junctions não são seguidos. "
                            + ("Houve lacunas; ausências não foram tratadas como exclusão nesses recortes." if incomplete else "Somente as pastas escolhidas."))

    def network(self):
        if self.system == "Windows":
            records = powershell(WIN_NETWORK, self.runner) or []
            records = records if isinstance(records, list) else [records]
            return [{"local_ip": valid_peer(r["LocalAddress"]), "local_port": int(r["LocalPort"]),
                     "ip": valid_peer(r["RemoteAddress"]), "port": int(r["RemotePort"]),
                     "pid": int(r["OwningProcess"])} for r in records[:500]], len(records) >= 501
        if self.system == "Linux":
            rows = []
            for filename, ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
                source = Path(filename).read_bytes()
                if len(source) > 524_288:
                    raise Unavailable("Tabela TCP excedeu o limite de leitura.")
                for line in source.decode("ascii").splitlines()[1:]:
                    fields = line.split()
                    if len(fields) < 4 or fields[3] != "01":
                        continue
                    def endpoint(token):
                        address, port = token.split(":")
                        raw = bytes.fromhex(address)
                        if sys.byteorder == "little":
                            raw = b"".join(raw[i:i+4][::-1] for i in range(0, len(raw), 4))
                        if len(raw) != (16 if ipv6 else 4):
                            raise ValueError("Endereço TCP incompleto.")
                        return valid_peer(str(ipaddress.ip_address(raw))), int(port, 16)
                    local_ip, local_port = endpoint(fields[1])
                    remote_ip, remote_port = endpoint(fields[2])
                    rows.append({"local_ip": local_ip, "local_port": local_port, "ip": remote_ip,
                                 "port": remote_port, "pid": None})
                    if len(rows) > 500:
                        return rows[:500], True
            return rows, False
        raise Unavailable("TCP detalhado não coberto neste sistema; arquivos continuam disponíveis.")

    def scan_network(self):
        records, bounded = self.network()
        for r in records:
            if not r["ip"] or not 1 <= r["port"] <= 65535 or not 0 <= r["local_port"] <= 65535:
                raise Unavailable("Endpoint incompleto.")
        def key(r):
            return json.dumps(r, sort_keys=True)
        previous = {key(r): r for r in self.store.get("tcp-state", [])}
        current = {key(r): r for r in records}
        for identifier in current.keys()-previous.keys():
            r = current[identifier]
            self.store.add_event("network_observed", "Conexão TCP estabelecida observada", "tcp-table", ip=r["ip"],
                                 metadata={**r, "peer_scope": peer_scope(r["ip"]), "direction": "não determinada",
                                           "limit": "Tabela amostrada: não captura conteúdo, bytes copiados ou origem física. IP pode representar NAT/VPN/proxy."})
        if not bounded:
            for identifier in previous.keys()-current.keys():
                r = previous[identifier]
                self.store.add_event("network_missing", "Conexão não aparece mais nesta amostra", "tcp-table", ip=r["ip"],
                                     metadata={**r, "limit": "Diferença entre amostras; não informa motivo do término nem quantidade transferida."})
        # Recorte truncado não apaga conexões observadas anteriormente.
        merged = {**previous, **current} if bounded else current
        self.store.set("tcp-state", list(merged.values())[-1000:])
        self.store.coverage("network", "partial" if bounded else "observed",
                            f"{len(records)} conexões TCP na amostra; até 500. Sem UDP, captura de pacotes ou volume transferido. "
                            + ("Limite alcançado; encerramentos não inferidos." if bounded else "Conexões curtas entre ciclos podem não aparecer."))

    def scan_auth(self):
        since = self.store.get("auth-since", (datetime.now(timezone.utc)-timedelta(minutes=15)).isoformat())
        if self.system == "Windows":
            value = powershell(windows_auth_script(since), self.runner)
            if not isinstance(value, dict) or not isinstance(value.get("events"), list) or type(value.get("bounded")) is not bool:
                raise Unavailable("Recorte de autenticação incompleto.")
            config = self.store.get("config", {})
            for row in sorted(value["events"], key=lambda r: r["time"]):
                event_id, data = int(row["id"]), row["data"]
                kind, title, severity = {
                    4624: ("auth_success", "Logon bem-sucedido registrado", "info"),
                    4625: ("auth_failure", "Tentativa de logon falhou", "attention"),
                    4672: ("privilege", "Privilégios especiais atribuídos ao logon", "attention"),
                    4720: ("account_created", "Conta criada", "attention"),
                    4732: ("group_changed", "Membro adicionado a grupo local", "attention"),
                    1102: ("audit_cleared", "Log de segurança foi limpo", "critical"),
                    4663: ("object_access", "Acesso ao objeto registrado pela auditoria", "info"),
                }.get(event_id, ("auth_other", "Evento de segurança", "info"))
                outside = after_hours(row["time"], config)
                if kind == "auth_success" and outside:
                    severity = "attention"
                ip = valid_peer(data.get("IpAddress", ""))
                account = clean(data.get("TargetUserName") or data.get("SubjectUserName"), 160)
                metadata = {"windows_event_id": event_id, "record_id": int(row["record"]),
                            "logon_type": clean(data.get("LogonType"), 20),
                            "logon_id": clean(data.get("TargetLogonId") or data.get("SubjectLogonId"), 80),
                            "peer_scope": peer_scope(ip), "after_hours": outside,
                            "access_mask": clean(data.get("AccessMask"), 40),
                            "object_type": clean(data.get("ObjectType"), 40),
                            "limit": "A fonte descreve o evento auditado. Logon/privilegio ou leitura de arquivo não prova invasão, cópia ou exfiltração. 4663 depende de auditoria/SACL prévia."}
                self.store.add_event(kind, title, "windows-security", severity=severity, event_at=row["time"],
                                     external_key=f"win:{row['record']}:{row['time']}:{event_id}", ip=ip, account=account,
                                     path=clean(data.get("ObjectName"), 1000), metadata=metadata)
            bounded = value["bounded"]
        elif self.system == "Linux":
            exe = shutil.which("journalctl")
            if not exe:
                raise Unavailable("journalctl indisponível.")
            output = self.runner([exe, "--no-pager", "--output=json", "--since", since, "-n", "201", "_COMM=sshd"])
            lines = output.splitlines()
            bounded = len(lines) >= 201
            for line in lines:
                row = json.loads(line)
                message = row.get("MESSAGE", "")
                match = re.search(r"\b(Accepted|Failed) (?:password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?(\S+) from (\S+) port (\d+)", str(message))
                if not match:
                    continue
                micros = int(row["__REALTIME_TIMESTAMP"])
                stamp = datetime.fromtimestamp(micros/1_000_000, timezone.utc).isoformat()
                success = match[1] == "Accepted"
                ip = valid_peer(match[3])
                outside = after_hours(stamp, self.store.get("config", {}))
                self.store.add_event("auth_success" if success else "auth_failure", "SSH aceito" if success else "SSH recusado",
                                     "linux-sshd", severity="attention" if not success or outside else "info", event_at=stamp,
                                     external_key="ssh:"+clean(row.get("__CURSOR") or hashlib.sha256((str(micros)+message).encode()).hexdigest(), 500),
                                     ip=ip, account=match[2], metadata={"after_hours": outside, "peer_scope": peer_scope(ip),
                                     "limit": "Somente padrões Accepted/Failed de sshd no journal acessível; mensagens brutas não são preservadas. Não comprova ausência de outros acessos."})
        else:
            raise Unavailable("Eventos de autenticação não cobertos neste sistema.")
        self.store.set("auth-since", (datetime.now(timezone.utc)-timedelta(seconds=60)).isoformat())
        self.store.coverage("authentication", "partial" if bounded else "observed",
                            "Recorte acessível e limitado a 201 registros/ciclo. Auditoria/retenção não são garantidas; ausência de eventos não prova ausência de ataque. "
                            + ("Limite atingido: registros podem ter sido omitidos." if bounded else "Consulta concluída."))

    def checkup(self):
        device = self.store.get("device")
        report = make_report(device["id"], device["alias"])
        self.store.set("latest_checkup", report)
        self.store.add_event("checkup", "Check-up local concluído", "netguard-checkup",
                             metadata={"counts": {s: sum(c["status"] == s for c in report["checks"]) for s in ("green", "yellow", "red", "unknown")},
                                       "limit": "Critérios do coletor; não executa varredura antimalware nem libera contenção."})
        return report

    def cycle(self):
        if not self.cycle_lock.acquire(blocking=False):
            raise ValueError("Já existe uma coleta em andamento.")
        try:
            started = now_stamp()
            for name, collector in (("files", self.scan_files), ("network", self.scan_network), ("authentication", self.scan_auth)):
                try:
                    collector()
                except (OSError, ValueError, TypeError, KeyError, Unavailable):
                    self.store.coverage(name, "unavailable", "Consulta falhou, faltou permissão/componente ou o recorte excedeu limites. Revise a fonte original.")
            self.store.set("heartbeat", {"started_at": started, "completed_at": now_stamp(),
                                         "running": bool(self.thread and self.thread.is_alive())})
            config = self.store.get("config", {})
            if config.get("auto_backup", True) and self.store.get("last_backup_day") != now_stamp()[:10]:
                try:
                    self.store.backup()
                    self.store.coverage("backup", "observed", "Pacote de evidências criado hoje (UTC); não é backup integral do computador.")
                except (OSError, ValueError):
                    self.store.coverage("backup", "unavailable", "Pacote não criado: limite ou erro local. Nenhum pacote antigo foi apagado.")
        finally:
            self.cycle_lock.release()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        def work():
            while not self.stop_event.is_set():
                try:
                    self.cycle()
                except (OSError, ValueError):
                    self.store.coverage("collector", "unavailable", "Ciclo não concluído; verifique armazenamento e configuração.")
                self.stop_event.wait(self.store.get("config", {}).get("interval", 30))
            previous = self.store.get("heartbeat", {})
            self.store.set("heartbeat", {**previous, "running": False, "stopped_at": now_stamp()})
        self.thread = threading.Thread(target=work, name="netguard-monitor", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=65)
