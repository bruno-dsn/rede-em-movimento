"""Coletor local, somente leitura, sem dependências e sem sondar outros hosts."""
from __future__ import annotations

import base64
import html
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

VERSION = "3.0.0"
MAX_BYTES = 262144
STATUSES = {"green", "yellow", "red", "unknown"}
LABELS = {"green": "Conferido", "yellow": "Atenção", "red": "Crítico", "unknown": "Não verificado"}
IDS = ("firewall", "antimalware", "listeners", "network", "authlogs", "updates")
TITLES = {
    "firewall": "Firewall do computador", "antimalware": "Proteção antimalware",
    "listeners": "Serviços TCP em escuta", "network": "Configuração de rede",
    "authlogs": "Falhas de autenticação · 24 horas", "updates": "Atualizações do sistema",
}
ACTIONS = {
    "firewall": "Peça ao responsável de TI para revisar perfis e regras. Valide de novo após qualquer ajuste.",
    "antimalware": "Confira o antivírus adotado pela empresa, seu modo de operação e atualização.",
    "listeners": "Confira a necessidade dos serviços. Restrinja acesso no firewall conforme a política da empresa.",
    "network": "Confira gateway, DNS, rede de visitantes e configurações do roteador com o responsável.",
    "authlogs": "Compare horários e contexto no sistema original. Falha de senha não comprova invasão.",
    "updates": "Abra o gerenciador de atualizações e confira pendências e reinicializações. Registre a evidência.",
}

# Scripts fixos: valores do relatório e argumentos do usuário nunca viram comandos.
PS = {
    "firewall": "@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { @{name=[string]$_.Name;enabled=[string]$_.Enabled;inbound=[string]$_.DefaultInboundAction} }) | ConvertTo-Json -Compress",
    "antimalware": "Get-MpComputerStatus | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress",
    "listeners": "@(Get-NetTCPConnection -State Listen | Select-Object -First 500 LocalAddress,LocalPort) | ConvertTo-Json -Compress",
    "network": "@(Get-NetIPConfiguration | ForEach-Object { @{gateway=([bool]($_.IPv4DefaultGateway -or $_.IPv6DefaultGateway));dns=([bool]$_.DNSServer.ServerAddresses)} }) | ConvertTo-Json -Compress",
    "authlogs": "try { $x=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 201 -ErrorAction Stop); @{count=$x.Count;bounded=($x.Count -ge 201)} | ConvertTo-Json -Compress } catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { @{count=0;bounded=$false} | ConvertTo-Json -Compress } else { throw } }",
    "updates": "@(Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1 | ForEach-Object { @{lastInstalled=$_.InstalledOn.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')} }) | ConvertTo-Json -Compress",
}


class Unavailable(Exception):
    """Consulta indisponível, com mensagem sem saída sensível do comando."""


def run_command(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, shell=False, capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise Unavailable("Consulta ausente, sem permissão ou excedeu 20 segundos.") from ex
    if result.returncode:
        raise Unavailable("A consulta não foi concluída; pode exigir permissão ou componente do sistema.")
    if len(result.stdout) > MAX_BYTES:
        raise Unavailable("Resposta excedeu o limite de leitura.")
    try:
        return result.stdout.decode("utf-8-sig", errors="strict").strip()
    except UnicodeError as ex:
        raise Unavailable("Resposta do sistema com codificação não reconhecida.") from ex


def ps_query(key: str, runner=run_command):
    exe = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not exe:
        raise Unavailable("PowerShell não encontrado.")
    prefix = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();"
    encoded = base64.b64encode((prefix + PS[key]).encode("utf-16-le")).decode("ascii")
    try:
        return json.loads(runner([exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]) or "null")
    except (ValueError, TypeError) as ex:
        raise Unavailable("Resposta incompleta da consulta.") from ex


def check(key: str, status: str, evidence: str, source: str, limit: str) -> dict:
    return {"id": key, "status": status, "title": TITLES[key], "evidence": evidence,
            "source": source, "limit": limit, "next_action": ACTIONS[key]}


def rows(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def assess_windows(key, raw):
    """Interpretação conservadora: cobertura parcial nunca produz verde."""
    source = {"firewall": "Get-NetFirewallProfile / ActiveStore", "antimalware": "Get-MpComputerStatus",
              "listeners": "Get-NetTCPConnection / Listen", "network": "Get-NetIPConfiguration",
              "authlogs": "Get-WinEvent / Security 4625", "updates": "Get-HotFix"}[key]
    if key == "firewall":
        records = rows(raw)
        if len(records) != 3 or {x["name"] for x in records} != {"Domain", "Private", "Public"}:
            raise Unavailable("Os três perfis não foram retornados.")
        enabled = [x["enabled"] for x in records]
        if any(v not in {"True", "False"} for v in enabled):
            raise Unavailable("Habilitação de algum perfil não foi determinada.")
        disabled = sum(x == "False" for x in enabled)
        status = "red" if disabled == 3 else "yellow" if disabled else "green"
        if not disabled and any(x.get("inbound") != "Block" for x in records):
            status = "yellow"
        evidence = f"{3-disabled}/3 perfis habilitados. " + "; ".join(f"{x['name']}: entrada padrão {x.get('inbound', 'desconhecida')}" for x in records)
        return check(key, status, evidence, source, "Não avalia cada regra, firewall de terceiros, roteador ou exposição pela internet.")
    if key == "antimalware":
        if not isinstance(raw, dict) or type(raw.get("RealTimeProtectionEnabled")) is not bool:
            raise Unavailable("Estado de proteção não retornado.")
        mode = raw.get("AMRunningMode")
        if mode != "Normal":
            return check(key, "yellow", "Defender fora do modo Normal; outro produto pode ser responsável.", source, "Não consulta o estado de antivírus de terceiros.")
        if type(raw.get("AntivirusEnabled")) is not bool or type(raw.get("AntivirusSignatureAge")) is not int:
            raise Unavailable("Estado ou idade das assinaturas ausente.")
        active = raw["AntivirusEnabled"] and raw["RealTimeProtectionEnabled"]
        age = raw["AntivirusSignatureAge"]
        if age < 0 or age > 100000:
            raise Unavailable("Idade das assinaturas não confiável.")
        status = "red" if not active else "yellow" if age > 7 else "green"
        return check(key, status, f"Modo Normal; proteção em tempo real {'ativa' if active else 'inativa'}; assinaturas com {age} dia(s).", source, "Verifica estado, não executa varredura nem comprova ausência de malware. Mais de 7 dias é uma regra própria de atenção.")
    if key == "listeners":
        records = rows(raw)
        if len(records) >= 500:
            raise Unavailable("Lista de serviços alcançou o limite de 500 entradas.")
        services = set()
        for item in records:
            address = ipaddress.ip_address(item["LocalAddress"].split("%")[0])
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            port = item["LocalPort"]
            if type(port) is not int or not 1 <= port <= 65535:
                raise Unavailable("Porta TCP inválida na consulta.")
            if not address.is_loopback:
                services.add(port)
        risky = services & {22, 23, 445, 3389, 5900}
        ports = ", ".join(map(str, sorted(services))) or "nenhuma"
        return check(key, "yellow" if risky else "green", f"Portas em interfaces além de loopback: {ports}.", source, "Escuta não prova acesso remoto: firewall, interfaces e roteador podem bloquear. Só TCP; não captura pacotes. Atenção em 22, 23, 445, 3389 ou 5900 é regra de revisão, não vulnerabilidade confirmada.")
    if key == "network":
        records = rows(raw)
        if not records or any(type(x.get("gateway")) is not bool or type(x.get("dns")) is not bool for x in records):
            raise Unavailable("Configuração incompleta.")
        configured = any(x["gateway"] and x["dns"] for x in records)
        return check(key, "green" if configured else "yellow", "Gateway e DNS configurados na mesma interface." if configured else "Nenhuma interface retornada com gateway e DNS juntos.", source, "Configuração não comprova conectividade, confiabilidade do DNS ou proteção do Wi-Fi. Nenhum teste externo foi enviado.")
    if key == "authlogs":
        if not isinstance(raw, dict) or type(raw.get("count")) is not int or type(raw.get("bounded")) is not bool or not 0 <= raw["count"] <= 201:
            raise Unavailable("Contagem de eventos ausente.")
        count, bounded = raw["count"], raw["bounded"]
        return check(key, "yellow", f"{'Pelo menos ' if bounded else ''}{count} falha(s) de logon registradas nas últimas 24 horas.", source, "Apenas log Security/4625 disponível. Zero não comprova auditoria habilitada, retenção íntegra ou ausência de ataque. Não coleta contas, IPs ou mensagens.")
    if key == "updates":
        records = rows(raw)
        stamp = records[0].get("lastInstalled") if records else None
        if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp):
            raise Unavailable("Nenhuma data de atualização foi retornada.")
        return check(key, "yellow", f"Última instalação retornada por Get-HotFix: {stamp}.", source, "Data histórica não indica pendências, suporte do sistema ou atualização completa; a revisão é manual.")
    raise ValueError("Verificação desconhecida.")


def collect_windows(query=ps_query):
    result = []
    for key in IDS:
        try:
            result.append(assess_windows(key, query(key)))
        except (Unavailable, ValueError, TypeError, KeyError, AttributeError) as ex:
            reason = str(ex) if isinstance(ex, Unavailable) else "Consulta incompleta ou com formato inesperado."
            result.append(check(key, "unknown", reason, "Consulta local Windows", "Não foi possível avaliar este controle; não indica que ele esteja aprovado."))
    return result


def collect_linux(runner=run_command, read_text=None):
    reader = read_text or (lambda p: Path(p).read_text(encoding="utf-8"))
    results = {key: check(key, "unknown", "Não coberto neste adaptador Linux.", "Adaptador Linux", "Revisão manual necessária.") for key in IDS}
    try:
        # Estado UFW é observado, mas não equivale a testar a política do host.
        if not shutil.which("ufw"):
            raise Unavailable("UFW não instalado; outros firewalls não foram avaliados.")
        value = runner([shutil.which("ufw"), "status", "verbose"])
        active = bool(re.search(r"(?im)^Status: active\s*$", value))
        results["firewall"] = check("firewall", "yellow", "UFW ativo; política precisa de revisão." if active else "UFW não retornou estado ativo.", "ufw status verbose", "Não interpreta todas as regras nem outros gerenciadores. Nenhuma regra foi alterada.")
    except (Unavailable, OSError, UnicodeError) as ex:
        results["firewall"]["evidence"] = str(ex) if isinstance(ex, Unavailable) else "Estado indisponível."
    try:
        services = set()
        entries = 0
        for filename, family in (("/proc/net/tcp", 4), ("/proc/net/tcp6", 6)):
            try:
                lines = reader(filename).splitlines()[1:]
            except FileNotFoundError:
                if family == 6:
                    continue
                raise
            for line in lines:
                entries += 1
                if entries > 10000:
                    raise Unavailable("Tabela de sockets excedeu o limite de leitura.")
                values = line.split()
                if len(values) < 4 or values[3] != "0A":
                    continue
                addr, port = values[1].split(":")
                if family == 4:
                    raw = bytes.fromhex(addr)
                    if sys.byteorder == "little":
                        raw = raw[::-1]
                else:
                    raw = b"".join(bytes.fromhex(addr[i:i+8])[::-1] if sys.byteorder == "little" else bytes.fromhex(addr[i:i+8]) for i in range(0, 32, 8))
                address = ipaddress.ip_address(raw)
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    address = address.ipv4_mapped
                if not address.is_loopback:
                    services.add(int(port, 16))
        ports = ", ".join(map(str, sorted(services))) or "nenhuma"
        results["listeners"] = check("listeners", "yellow" if services & {22, 23, 445, 3389, 5900} else "green", f"Portas em interfaces além de loopback: {ports}.", "/proc/net/tcp e tcp6", "Apenas namespace atual. Escuta não comprova acesso pela rede ou internet. Só TCP; endereços e processos não são exportados.")
    except (Unavailable, OSError, UnicodeError, ValueError, IndexError, AttributeError):
        results["listeners"]["evidence"] = "Tabela de sockets não disponível ou incompleta."
    try:
        ipv4 = reader("/proc/net/route").splitlines()[1:]
        gateway = any(len(row.split()) >= 4 and row.split()[1] == "00000000" and int(row.split()[3], 16) & 2 for row in ipv4)
        dns = any(re.match(r"^\s*nameserver\s+\S+", line) for line in reader("/etc/resolv.conf").splitlines())
        results["network"] = check("network", "green" if gateway and dns else "yellow", f"Rota padrão IPv4 {'presente' if gateway else 'não encontrada'}; configuração de resolvedor {'presente' if dns else 'não encontrada'}.", "/proc/net/route e /etc/resolv.conf", "Não cobre rotas IPv6, política de roteamento, VPN ou conectividade. Um resolvedor local pode estar indisponível. Nenhum pacote de teste enviado.")
    except (OSError, UnicodeError, ValueError):
        results["network"]["evidence"] = "Configuração de rede não disponível."
    # journalctl indisponível, vazio ou incompleto não vira 'sem falhas'.
    try:
        exe = shutil.which("journalctl")
        if not exe:
            raise Unavailable("journalctl não disponível.")
        lines = runner([exe, "--since", "24 hours ago", "--no-pager", "--output=json", "--lines=201", "_COMM=sshd"]).splitlines()
        if not lines:
            raise Unavailable("Nenhum registro de sshd acessível; cobertura da fonte não confirmada.")
        count = 0
        for line in lines:
            msg = json.loads(line).get("MESSAGE", "")
            if not isinstance(msg, str):
                raise Unavailable("Mensagem do journal fora do formato previsto.")
            if re.search(r"Failed (password|publickey)|authentication failure", msg):
                count += 1
        results["authlogs"] = check("authlogs", "yellow", f"{count} falha(s) em {len(lines)} registros de sshd lidos.", "journalctl / sshd / 24h / até 201 registros", "Recorte limitado, apenas sshd e padrões textuais. Zero falhas no recorte não garante cobertura; não exporta mensagens, contas ou IPs.")
    except (Unavailable, OSError, ValueError, AttributeError):
        results["authlogs"]["evidence"] = "Fonte sshd ausente, sem permissão ou com cobertura desconhecida."
    return [results[key] for key in IDS]


def make_report(device_id, alias, system=None, checks=None, now=None, mode="observed"):
    system = system or platform.system()
    system = system if system in {"Windows", "Linux", "Darwin"} else "Other"
    if checks is None:
        checks = collect_windows() if system == "Windows" else collect_linux() if system == "Linux" else [
            check(key, "unknown", "Sistema ainda não suportado.", "Adaptador ausente", "Sem avaliação automática neste sistema.") for key in IDS]
    result = {"format": "netguard-checkup", "schema_version": 1, "collector_version": VERSION,
              "mode": mode, "device_id": device_id, "device_alias": alias,
              "platform": system, "created_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds").replace("+00:00", "Z"),
              "checks": checks}
    return validate_report(result)


def validate_report(report):
    keys = {"format", "schema_version", "collector_version", "mode", "device_id", "device_alias", "platform", "created_at", "checks"}
    if not isinstance(report, dict) or set(report) != keys or report["format"] != "netguard-checkup" or type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise ValueError("Formato de check-up inválido.")
    if report["mode"] not in {"observed", "demo"} or report["platform"] not in {"Windows", "Linux", "Darwin", "Other"}:
        raise ValueError("Origem do check-up inválida.")
    for key, bound in (("collector_version", 30), ("device_alias", 80)):
        if not isinstance(report[key], str) or not report[key].strip() or len(report[key]) > bound or any(ord(c) < 32 for c in report[key]):
            raise ValueError("Identificação inválida.")
    if not isinstance(report["device_id"], str) or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", report["device_id"]):
        raise ValueError("Identificador local inválido.")
    stamp = report["created_at"]
    if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp):
        raise ValueError("Horário UTC inválido.")
    datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    checks = report["checks"]
    if not isinstance(checks, list) or len(checks) != len(IDS) or {x.get("id") for x in checks if isinstance(x, dict)} != set(IDS):
        raise ValueError("Cobertura do check-up inválida.")
    for item in checks:
        if not isinstance(item, dict) or set(item) != {"id", "status", "title", "evidence", "source", "limit", "next_action"} or item["status"] not in STATUSES:
            raise ValueError("Verificação inválida.")
        for field in ("title", "evidence", "source", "limit", "next_action"):
            if not isinstance(item[field], str) or not item[field].strip() or len(item[field]) > 4000 or any(ord(c) < 32 for c in item[field]):
                raise ValueError("Texto de verificação inválido.")
    return report


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value or key in {"__proto__", "constructor", "prototype"}:
            raise ValueError("Chave JSON repetida ou proibida.")
        value[key] = item
    return value


def load_report(path):
    file = Path(path)
    if file.is_symlink() or not file.is_file() or file.stat().st_size > MAX_BYTES:
        raise ValueError("Use um relatório regular de até 256 KB.")
    try:
        return validate_report(json.loads(file.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs))
    except (RecursionError, TypeError) as ex:
        raise ValueError("Relatório muito complexo ou fora do formato previsto.") from ex


def compare_reports(previous, current):
    validate_report(previous)
    validate_report(current)
    if any(previous[k] != current[k] for k in ("device_id", "platform", "mode")) or current["created_at"] <= previous["created_at"]:
        raise ValueError("Compare a mesma origem e computador, do mais antigo para o mais recente.")
    old = {c["id"]: c for c in previous["checks"]}
    return [{"id": c["id"], "before": old[c["id"]]["status"], "after": c["status"]} for c in current["checks"] if old[c["id"]]["status"] != c["status"]]


def report_html(report, previous=None):
    validate_report(report)
    e = html.escape
    counts = Counter(c["status"] for c in report["checks"])
    cards = "".join(f'<article class="{c["status"]}"><span>{LABELS[c["status"]]}</span><h2>{e(c["title"])}</h2><p>{e(c["evidence"])}</p><p><b>Fonte:</b> {e(c["source"])}</p><p><b>O que isso não verifica:</b> {e(c["limit"])}</p><p><b>Próximo passo:</b> {e(c["next_action"])}</p></article>' for c in report["checks"])
    changes = compare_reports(previous, report) if previous else None
    change_html = "Sem check-up anterior comparável." if changes is None else "Sem mudança de estado entre as seis verificações." if not changes else "<ul>" + "".join(f'<li>{e(TITLES[c["id"]])}: {LABELS[c["before"]]} → {LABELS[c["after"]]}</li>' for c in changes) + "</ul>"
    return '<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\';style-src \'unsafe-inline\';base-uri \'none\';form-action \'none\'"><title>NetGuard · Check-up local</title><style>body{font:17px/1.6 system-ui;background:#f7eacb;color:#172e24;margin:auto;padding:2rem;max-width:1050px}h1{font-size:clamp(2rem,5vw,3.5rem)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:1rem}article{background:#fffdf4;padding:1.3rem;border:1px solid #b4b8a7;border-top:7px solid #737b77;border-radius:12px}article.green{border-top-color:#28754a}article.yellow{border-top-color:#b07700}article.red{border-top-color:#b23c33}span{font-weight:bold}p{overflow-wrap:anywhere}@media print{article{break-inside:avoid}body{background:white}}</style><h1>Seu check-up, explicado.</h1>' + f'<p><b>{"EXEMPLO FICTÍCIO" if report["mode"] == "demo" else "COLETA LOCAL · SOMENTE LEITURA"}</b> · {e(report["device_alias"])} · {e(report["platform"])} · {e(report["created_at"])} UTC</p><p>{counts["green"]} conferidos · {counts["yellow"]} atenção · {counts["red"]} críticos · {counts["unknown"]} não verificados.</p><p>Um retrato do momento da coleta. Verde aprova somente o critério descrito; não garante que o computador ou a empresa estejam seguros. Este arquivo não filtra tráfego ou altera configurações.</p><h2>Mudanças desde o anterior</h2><div>{change_html}</div><div class="grid">{cards}</div><p>Guarde os JSONs para comparar no painel NetGuard. Revise a autorização e os dados antes de compartilhar.</p></html>'


def private_write(path: Path, text: str, replace=False):
    """Cria arquivos privados; substituições próprias usam renomeação atômica."""
    if path.is_symlink():
        raise ValueError("Destino não pode ser um link simbólico.")
    target = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp") if replace else path
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        if replace:
            os.replace(target, path)
    finally:
        if replace and target.exists():
            target.unlink()


def history(directory: Path, device_id):
    reports = []
    for path in sorted(directory.glob("checkup-*.json"))[-1000:]:
        try:
            report = load_report(path)
            if report["device_id"] == device_id and report["mode"] == "observed":
                reports.append(report)
        except (OSError, ValueError, UnicodeError):
            continue
    return sorted(reports, key=lambda r: r["created_at"])[-30:]
