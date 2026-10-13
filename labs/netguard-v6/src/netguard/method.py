"""Roteiro educacional próprio: evidências, triagem declarada e revisão."""

import html
import json
from pathlib import Path

from netguard.notebook import NOTE_FIELDS, encode_notebook

CATALOG = json.loads((Path(__file__).resolve().parents[2] / "data/defense-method.json").read_text(encoding="utf-8"))


def classify_claim(claim_id: str, category: str) -> dict:
    claim = next((claim for claim in CATALOG["claims"] if claim["id"] == claim_id), None)
    if claim is None or category not in CATALOG["categories"]:
        raise ValueError("Escolha um cartão e uma categoria válidos.")
    return {"correct": claim["category"] == category, "expected": CATALOG["categories"][claim["category"]], "why": claim["why"]}


def prioritize(impact: str, ongoing: str) -> dict:
    if impact not in ("baixo", "moderado", "alto") or ongoing not in ("sim", "nao", "desconhecido"):
        raise ValueError("Condições de triagem inválidas.")
    if impact == "alto" and ongoing == "sim":
        return {"level": "Acionar resposta agora", "why": "Impacto potencial alto e atividade em andamento confirmada pedem acionamento imediato dos responsáveis pelo procedimento de resposta.", "next": "Coordenar contenção autorizada, preservar registros relevantes e acompanhar o efeito no serviço."}
    if impact == "alto" or ongoing == "sim":
        return {"level": "Avaliar com prioridade", "why": "Há potencial impacto alto ou atividade em andamento. A combinação pede avaliação prioritária, mesmo sem uma conclusão sobre a causa.", "next": "Confirmar escopo, processo de negócio e responsáveis; decidir medidas conforme o procedimento da organização."}
    if ongoing == "desconhecido":
        return {"level": "Confirmar atividade e contexto", "why": "O estado da atividade ainda é desconhecido. Busque a informação necessária para decidir a urgência.", "next": "Verificar fontes atuais e responsáveis; aumentar a prioridade se surgirem novos sinais de impacto."}
    return {"level": "Planejar e verificar", "why": "Nas condições declaradas, planeje verificações e correções com responsáveis. Esta resposta não encerra o caso nem comprova baixo risco.", "next": "Definir próximo teste, prazo de revisão e evidência esperada."}


def draft_review(notes: dict) -> dict:
    missing = [key for key in NOTE_FIELDS if not isinstance(notes.get(key), str) or not notes[key].strip()]
    return {"filled": len(NOTE_FIELDS) - len(missing), "missing": missing}


def method_report(investigation: dict, notes: dict, case: str, impact: str, ongoing: str) -> bytes:
    encode_notebook(investigation, notes, case)
    triage, review = prioritize(impact, ongoing), draft_review(notes)
    labels = ("Observações e identificação da cópia", "Hipóteses e alternativas", "Escopo, perguntas e prioridade", "Ação proposta, validação e melhoria")
    articles = "".join(f'<article><h2>{label}</h2><p>{html.escape(notes[key] or "Sem anotação.")}</p></article>' for key, label in zip(NOTE_FIELDS, labels, strict=True))
    steps = "".join(f'<article><h3>{html.escape(step["title"])}</h3><p>{html.escape(step["method"])} · relação de estudo: {html.escape(step["discipline"])}</p><p>Entregável: {html.escape(step["deliverable"])}</p></article>' for step in CATALOG["steps"])
    refs = "\n".join(f'{ref["name"]}: {ref["url"]}' for ref in CATALOG["references"])
    return f'''<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';base-uri 'none';form-action 'none'"><title>NetGuard · Roteiro de defesa</title><style>body{{font:16px/1.6 system-ui;color:#1b231d;max-width:900px;margin:32px auto;padding:0 24px}}article{{border:1px solid #d1c09f;padding:20px;margin:18px 0}}p{{white-space:pre-wrap;overflow-wrap:anywhere}}h1,h2{{color:#2f6b3f}}</style><h1>Roteiro de defesa · {html.escape(case)}</h1><p>Registro educacional. Nenhuma alteração de infraestrutura foi executada. {review["filled"]}/4 campos com texto; preenchimento não atesta qualidade nem encerramento.</p><p>SHA-256 da cópia recebida: {html.escape(investigation["sha256"])}\n{investigation["bytes"]} bytes · {len(investigation["events"])} eventos · horários normalizados em UTC</p><h2>Triagem declarada</h2><p>Impacto potencial: {html.escape(impact)} · atividade em andamento: {html.escape(ongoing)}</p><p>{html.escape(triage["level"])}. {html.escape(triage["why"])} {html.escape(triage["next"])}</p>{articles}<h2>Roteiro usado</h2>{steps}<p>{html.escape(CATALOG["scope"])}</p><p>{html.escape(CATALOG["grade"])}</p><p>{html.escape(refs)}</p></html>'''.encode("utf-8")
