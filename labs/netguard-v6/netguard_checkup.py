#!/usr/bin/env python3
"""Execute com Python 3.12+: python netguard_checkup.py --open."""
import argparse
import json
import os
import sys
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from netguard.checkup import history, load_report, make_report, private_write, report_html, unique_pairs  # noqa: E402


def main(argv=None):
    if sys.version_info < (3, 12):
        raise ValueError("Instale Python 3.12 ou superior.")
    parser = argparse.ArgumentParser(description="NetGuard: check-up local somente leitura. Não altera a proteção nem sonda a rede.")
    parser.add_argument("--directory", type=Path, default=Path.home() / "NetGuard-Reports", help="Pasta local privada dos relatórios")
    parser.add_argument("--alias", default="Meu computador", help="Apelido de até 80 caracteres, sem hostname automático")
    parser.add_argument("--daily", action="store_true", help="No máximo uma coleta por dia local nesta pasta")
    parser.add_argument("--open", action="store_true", help="Abrir relatório HTML local no navegador")
    parser.add_argument("--validate", type=Path, help="Validar um JSON existente, sem coletar")
    args = parser.parse_args(argv)
    if args.validate:
        load_report(args.validate)
        print("Relatório válido.")
        return 0
    directory = args.directory.expanduser().absolute()
    if directory.is_symlink():
        raise ValueError("A pasta de relatórios não pode ser um link simbólico.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt" and directory.stat().st_mode & 0o077:
        raise ValueError("A pasta deve ser privada (permissões 700). Use outra pasta ou ajuste suas permissões.")
    identity = directory / "device.json"
    if not identity.exists():
        private_write(identity, json.dumps({"device_id": str(uuid.uuid4())}))
    if identity.is_symlink() or identity.stat().st_size > 200:
        raise ValueError("Identidade local inválida.")
    device_id = json.loads(identity.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)["device_id"]
    past = history(directory, device_id)
    now = datetime.now(timezone.utc)
    today = now.astimezone().date()
    if args.daily and past and datetime.fromisoformat(past[-1]["created_at"].replace("Z", "+00:00")).astimezone().date() == today:
        print("Já existe check-up de hoje. Nenhuma nova coleta foi feita.")
        return 0
    report = make_report(device_id, args.alias, now=now)
    stamp = now.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
    json_file = directory / f"checkup-{stamp}.json"
    html_file = directory / f"checkup-{stamp}.html"
    previous = past[-1] if past and past[-1]["platform"] == report["platform"] and past[-1]["created_at"] < report["created_at"] else None
    private_write(json_file, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    private_write(html_file, report_html(report, previous))
    # Bundle limitado ao dispositivo atual, sem apagar relatórios individuais.
    private_write(directory / "historico.json", json.dumps({"format": "netguard-history", "schema_version": 1, "reports": (past + [report])[-30:]}, ensure_ascii=False, indent=2) + "\n", replace=True)
    print(f"Check-up concluído, sem mudanças no sistema.\nJSON: {json_file}\nHTML: {html_file}\nHistórico (até 30 coletas): {directory / 'historico.json'}")
    if args.open:
        webbrowser.open(html_file.as_uri())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, UnicodeError) as error:
        print(f"Não foi possível concluir: {error}", file=sys.stderr)
        sys.exit(1)
