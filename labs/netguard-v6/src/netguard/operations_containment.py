"""Contenção manual, opcional, Windows. Sem resposta ofensiva ou bloqueio automático."""
from __future__ import annotations

import ipaddress
import platform
import re
import threading
import uuid

from .checkup import Unavailable, run_command
from .operations_monitor import powershell
from .operations_store import now_stamp


def peer_target(value):
    address = ipaddress.ip_address(value)
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local or address.is_reserved:
        raise ValueError("Este endereço não pode ser bloqueado pelo adaptador.")
    return str(address)


def firewall_script(identifier, mode, target, release=False):
    if not re.fullmatch(r"[a-f0-9]{32}", identifier) or mode not in {"peer", "isolate"}:
        raise ValueError("Plano inválido.")
    target = peer_target(target) if mode == "peer" else "Any"
    names = ["NGO-"+identifier+"-In", "NGO-"+identifier+"-Out"]
    listed = ",".join("'"+name+"'" for name in names)
    admin = "$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required'};"
    remove = f"foreach($n in @({listed})) {{ Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue | Where-Object {{$_.Group -eq 'NetGuard Operations'}} | Remove-NetFirewallRule -ErrorAction Stop }};"
    if release:
        return admin+remove+f"$left=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {{$_.Name -in @({listed})}}); if($left.Count -ne 0){{throw 'Rules remain'}}; @{{released=$true}} | ConvertTo-Json -Compress"
    profiles = "$p=@(Get-NetFirewallProfile -PolicyStore ActiveStore); if($p.Count -ne 3 -or @($p|Where-Object { $_.Enabled -ne 'True' }).Count -ne 0){throw 'Firewall profiles must be enabled'};"
    create = ";".join(f"New-NetFirewallRule -Name '{name}' -DisplayName 'NetGuard Operations {identifier}' -Group 'NetGuard Operations' -Direction {direction} -Action Block -RemoteAddress '{target}' -Profile Any -Protocol Any -Enabled True -ErrorAction Stop | Out-Null"
                      for name,direction in zip(names, ("Inbound", "Outbound"), strict=True))
    verify = f"$r=@(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {{$_.Name -in @({listed}) -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block'}}); if($r.Count -ne 2){{throw 'Effective rules not found'}};"
    # Em falha tenta desfazer somente as duas regras geradas. Estado fica failed e exige reconciliação.
    return admin+profiles+"try { "+create+";"+verify+" @{rules=2;validation='effective-rules-only'} | ConvertTo-Json -Compress } catch { "+remove+" throw }"


class Containment:
    def __init__(self, store, *, enabled=False, system=None, runner=run_command):
        self.store, self.enabled = store, enabled
        self.system, self.runner = system or platform.system(), runner
        self.lock = threading.Lock()

    def capabilities(self):
        return {"enabled": self.enabled and self.system == "Windows", "system": self.system,
                "automatic": False, "confirmation": "APLICAR "+self.store.get("device")["id"][:8],
                "limit": "Apenas ação manual no computador local. Regras efetivas precisam de teste de conectividade independente; não elimina malware. Não libera por varredura nem por temporizador."}

    def plan(self, event_id, mode, actor):
        event = self.store.investigation(event_id)["event"]
        if mode not in {"peer", "isolate"}:
            raise ValueError("Selecione bloqueio do IP ou isolamento do computador.")
        target = peer_target(event["ip"]) if mode == "peer" else "Any"
        identifier, stamp = uuid.uuid4().hex, now_stamp()
        with self.store.db() as db:
            active = db.execute("SELECT 1 FROM containment WHERE mode=? AND target=? AND status IN ('planned','applying','applied_unverified','failed','release_failed')", (mode,target)).fetchone()
            if active:
                raise ValueError("Já existe um plano ativo para este alvo. Revise-o antes de criar outro.")
            db.execute("INSERT INTO containment VALUES(?,?,?,?,?,?,?,?)",
                       (identifier, event_id, mode, target, "planned", actor, stamp, stamp))
        self.store.audit("containment_planned", actor, {"id": identifier, "event_id": event_id, "mode": mode})
        return {"id": identifier, "status": "planned", "effect": "Nenhuma conexão foi bloqueada."}

    def record(self, identifier):
        if not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise ValueError("Plano inválido.")
        with self.store.db() as db:
            row = db.execute("SELECT * FROM containment WHERE id=?", (identifier,)).fetchone()
            if not row:
                raise ValueError("Plano não encontrado.")
            return dict(row)

    def cancel(self, identifier, actor):
        with self.lock:
            return self._cancel(identifier, actor)

    def _cancel(self, identifier, actor):
        if self.record(identifier)["status"] != "planned":
            raise ValueError("Somente um plano sem aplicação pode ser cancelado.")
        self.state(identifier, "cancelled")
        self.store.audit("containment_cancelled", actor, {"id": identifier})
        return {"status": "cancelled", "effect": "Plano encerrado sem modificar regras."}

    def state(self, identifier, status):
        with self.store.db() as db:
            db.execute("UPDATE containment SET status=?,updated_at=? WHERE id=?", (status,now_stamp(),identifier))

    def apply(self, identifier, actor, password, confirmation, impact_acknowledged):
        with self.lock:
            return self._apply(identifier, actor, password, confirmation, impact_acknowledged)

    def _apply(self, identifier, actor, password, confirmation, impact_acknowledged):
        if not self.capabilities()["enabled"]:
            raise ValueError("Adaptador real desabilitado. Requer Windows e --enable-containment; nenhuma regra foi aplicada.")
        if not self.store.verify_user(actor, password):
            raise ValueError("Credenciais inválidas.")
        if confirmation != self.capabilities()["confirmation"] or impact_acknowledged is not True:
            raise ValueError("Digite a confirmação do equipamento e reconheça o impacto.")
        plan = self.record(identifier)
        if plan["status"] != "planned":
            raise ValueError("Somente um plano ainda não aplicado pode ser executado.")
        if self.store.investigation(plan["event_id"])["event"]["disposition"] != "incident":
            raise ValueError("Registre a decisão Incidente confirmado e seu contexto antes de aplicar.")
        self.state(identifier, "applying")
        self.store.audit("containment_requested", actor, {"id": identifier})
        try:
            result = powershell(firewall_script(identifier, plan["mode"], plan["target"]), self.runner)
            if not isinstance(result, dict) or result.get("rules") != 2:
                raise Unavailable("Regras não confirmadas.")
        except (Unavailable, OSError, ValueError):
            self.state(identifier, "failed")
            self.store.audit("containment_failed", actor, {"id": identifier})
            raise ValueError("Aplicação não confirmada. Confira as regras NGO deste plano e use release; não suponha isolamento.") from None
        self.state(identifier, "applied_unverified")
        self.store.audit("containment_rules_applied", actor, {"id": identifier})
        return {"status": "applied_unverified", "effect": "Duas regras de bloqueio encontradas no ActiveStore. Teste a contenção de outro equipamento autorizado; não é prova de isolamento completo."}

    def release(self, identifier, actor, password, note):
        with self.lock:
            return self._release(identifier, actor, password, note)

    def _release(self, identifier, actor, password, note):
        if not self.capabilities()["enabled"] or not self.store.verify_user(actor, password):
            raise ValueError("Adaptador indisponível ou credenciais inválidas.")
        if not isinstance(note, str) or not 20 <= len(note.strip()) <= 2000:
            raise ValueError("Registre de 20 a 2.000 caracteres sobre validação/recuperação.")
        plan = self.record(identifier)
        if plan["status"] not in {"applying", "applied_unverified", "failed", "release_failed"}:
            raise ValueError("Este plano não tem aplicação pendente de recuperação; cancele planos ainda não aplicados.")
        try:
            result = powershell(firewall_script(identifier, plan["mode"], plan["target"], release=True), self.runner)
            if not isinstance(result, dict) or result.get("released") is not True:
                raise Unavailable("Remoção não confirmada.")
        except (Unavailable, OSError, ValueError):
            self.state(identifier, "release_failed")
            raise ValueError("Remoção não confirmada; revise localmente as duas regras NGO deste plano.") from None
        self.state(identifier, "released")
        self.store.audit("containment_released", actor, {"id": identifier, "note": note[:2000]})
        return {"status": "released", "effect": "Removidas somente as regras deste plano. A decisão de recuperação foi registrada, sem certificação de sistema limpo."}
