from pathlib import Path

import pytest

from netguard.investigation import investigate
from netguard.method import CATALOG, classify_claim, draft_review, method_report, prioritize
from netguard.notebook import NOTE_FIELDS

ROOT = Path(__file__).resolve().parents[1]


def test_grade_mapping_and_cards_are_grounded_in_the_synthetic_case():
    events = {event["event_id"] for event in investigate((ROOT / "data/caso-financeiro-ficticio.csv").read_bytes())["events"]}
    assert len(CATALOG["steps"]) == 6
    assert "2022.2" in CATALOG["grade"]
    for claim in CATALOG["claims"]:
        assert claim["event"] in events
        assert classify_claim(claim["id"], claim["category"])["correct"] is True
    assert classify_claim("porta", "observacao")["correct"] is False
    assert "não tem sessão" in classify_claim("porta", "hipotese")["why"]


@pytest.mark.parametrize("impact,ongoing,level", [
    ("alto", "sim", "Acionar resposta agora"),
    ("alto", "desconhecido", "Avaliar com prioridade"),
    ("moderado", "sim", "Avaliar com prioridade"),
    ("baixo", "desconhecido", "Confirmar atividade e contexto"),
    ("moderado", "nao", "Planejar e verificar"),
])
def test_qualitative_triage_distinguishes_missing_information(impact, ongoing, level):
    assert prioritize(impact, ongoing)["level"] == level


def test_invalid_triage_does_not_produce_a_priority():
    with pytest.raises(ValueError):
        prioritize("certeza", "sim")
    with pytest.raises(ValueError):
        classify_claim("porta", "certeza")


def test_report_escapes_user_notes_and_keeps_file_identity_and_limits():
    result = investigate((ROOT / "data/caso-financeiro-ficticio.csv").read_bytes(), shared_session_namespace=True)
    notes = dict.fromkeys(NOTE_FIELDS, "")
    notes["observacoes"] = '<script>alert("teste")</script>'
    assert draft_review(notes)["filled"] == 1
    report = method_report(result, notes, "Caso <img>", "alto", "desconhecido").decode()
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "Caso &lt;img&gt;" in report
    assert result["sha256"] in report
    assert "não atesta qualidade" in report
    assert "default-src 'none'" in report
    notes["observacoes"] = " "
    assert draft_review(notes)["filled"] == 0
