"""Exportação sem script ativo: texto escapado e CSV limitado ao contrato de autenticação."""
import csv
import html
import io
import json


def report_html(report, run):
    def e(value):
        return html.escape(str(value), quote=True)
    fields = {"Observação": report["observation"], "Explicação alternativa": report["alternative"],
              "Correção": report["correction"], "Limites": report["limits"], "Próximo passo": report["next_step"]}
    selected = [ev for part in run["variants"] for ev in part["events"] if ev["id"] in report["evidence_ids"]]
    rows = "".join(f"<tr><td>{e(ev['id'])}</td><td>{e(ev['origin'])}</td><td>{e(ev['reason'])}</td><td>{e(ev.get('result', ev['status']))}</td></tr>" for ev in selected)
    checks = "".join(f"<li>{e(c['name'])}: observado {e(c['actual'])}, esperado {e(c['expected'])}; {'passou' if c['passed'] else 'divergiu'}.</li>" for c in run["checks"])
    return ("<!doctype html><html lang='pt-BR'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
            "<title>NetGuard · Relatório Empresa Viva</title><style>body{max-width:960px;margin:40px auto;padding:20px;font:17px/1.6 system-ui;color:#172d3e}h1{line-height:1.2}p{white-space:pre-wrap}td,th{padding:10px;text-align:left;border:1px solid #ccc;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;font-size:13px}</style>"
            f"<h1>NetGuard · Empresa Viva</h1><p>Relatório de estudo. Dados fictícios. Origem: {e(run['mode'])}.</p>"
            f"<p>Missão: {e(run['mission_id'])} · Execução: {e(run['id'])}<br>Conclusão declarada: {e(report['conclusion'])}<br>Hash do código: {e(run['code_sha256'])}</p>"
            + "".join(f"<h2>{e(k)}</h2><p>{e(v)}</p>" for k, v in fields.items())
            + f"<h2>Evidências citadas</h2><table><thead><tr><th>ID</th><th>Origem</th><th>Observação</th><th>Resultado</th></tr></thead><tbody>{rows}</tbody></table><h2>Verificações</h2><ul>{checks}</ul>"
            + f"<p>{e(run['limit'])}</p><p>{e(report['assessment_limit'])}</p></html>")


def authentication_csv(run):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("timestamp", "usuario", "ip", "resultado"))
    # Só a variante corrigida e os probes de login: sem alertas derivados ou mistura de versões.
    for event in run["variants"][1]["events"]:
        if event["category"] == "probe" and "/api/login" in event["request"]:
            writer.writerow((event["timestamp"], event["actor"], event["source_ip"], "sucesso" if event["status"] == 200 else "falha"))
    return output.getvalue()


def evidence_json(run):
    return json.dumps(run, ensure_ascii=False, indent=2, allow_nan=False)
