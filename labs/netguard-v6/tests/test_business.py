import hashlib
import http.client
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from netguard.business import Business, safe_name, stable_read
from netguard.operations_monitor import Monitor
from netguard.operations_server import OperationsServer
from netguard.operations_store import Store

PASSWORD = "senha-local-para-testes-123"


@pytest.fixture
def setup(tmp_path):
    store = Store(tmp_path / "state")
    store.init_user("operador", PASSWORD)
    root = tmp_path / "chosen"
    root.mkdir()
    (root / "documento.txt").write_bytes(b"trabalho ficticio v1")
    (root / "subpasta").mkdir()
    (root / "subpasta" / "outro.txt").write_bytes(b"mais um documento")
    store.set("config", {"roots": [str(root)], "interval": 30, "auto_backup": False})
    return store, root, Business(store)


def status(business, identifier):
    return next(c for c in business.summary()["controls"] if c["id"] == identifier)["status"]


def test_copy_restore_preserves_current_original_and_verifies_older_bytes(setup):
    store, root, business = setup
    assert status(business, "backup") == "unknown"
    pack = business.snapshot("operador")
    assert pack["files"] == 2
    assert status(business, "backup") == "attention"
    (root / "documento.txt").write_bytes(b"trabalho ficticio v2")
    result = business.restore(pack["id"], "operador")
    output = Path(result["destination"])
    assert output.is_relative_to(store.directory / "recovery-tests")
    assert (output / "pasta-1" / "documento.txt").read_bytes() == b"trabalho ficticio v1"
    assert (root / "documento.txt").read_bytes() == b"trabalho ficticio v2"
    assert result["status"] == "verified" and result["files"] == 2
    assert status(business, "backup") == "reviewed"
    second = business.restore(pack["id"], "operador")
    assert second["destination"] != result["destination"]
    assert len(business.summary()["tests"]) == 2


def test_tampered_copy_is_rejected_and_failed_result_replaces_previous_success(setup):
    _, _, business = setup
    pack = business.snapshot("operador")
    business.restore(pack["id"], "operador")
    path = business.packs / (pack["id"] + ".zip")
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="mudou"):
        business.restore(pack["id"], "operador")
    assert status(business, "backup") == "critical"
    assert business.summary()["tests"][0]["status"] == "failed"


def test_stale_copy_needs_attention_even_after_successful_restore(setup):
    store, _, business = setup
    pack = business.snapshot("operador")
    business.restore(pack["id"], "operador")
    later = Business(store, clock=lambda: datetime.now(timezone.utc) + timedelta(days=2))
    assert status(later, "backup") == "attention"


def test_reviews_are_append_only_manual_and_expire(setup):
    store, _, business = setup
    business.review("access", "reviewed", "Responsável", "Conferi MFA e contas no serviço fictício.", "operador")
    assert status(business, "access") == "reviewed"
    business.review("access", "attention", "Responsável", "Uma conta antiga precisa de aprovação para retirada.", "operador")
    assert len(business.summary()["reviews"]) == 2
    assert status(business, "access") == "attention"
    later = Business(store, clock=lambda: datetime.now(timezone.utc) + timedelta(days=31))
    assert status(later, "access") == "attention"
    with pytest.raises(ValueError):
        business.review("backup", "reviewed", "Pessoa", "Não substitui o teste de restauração.", "operador")


def test_profile_inventory_goals_are_bounded_and_persist(setup):
    store, _, business = setup
    profile = {"name": "Cartório fictício", "sector": "cartorio", "owner": "Pessoa de teste",
               "rpo_hours": 8, "rto_minutes": 120,
               "assets": [{"name": "PC", "purpose": "Documentos", "owner": "Pessoa"}]}
    business.profile(profile, "operador")
    assert Business(store).summary()["profile"] == profile
    for value in [True, 0, 169, 1.5]:
        with pytest.raises(ValueError):
            business.profile({**profile, "rpo_hours": value}, "operador")
    with pytest.raises(ValueError):
        business.profile({**profile, "assets": [{}]}, "operador")


def test_scope_limits_fail_without_partial_success(setup, monkeypatch):
    store, root, business = setup
    monkeypatch.setattr("netguard.business.MAX_FILE", 3)
    with pytest.raises(ValueError):
        business.snapshot("operador")
    assert business.summary()["packs"] == []
    assert list(business.packs.iterdir()) == []
    store.set("config", {"roots": [str(store.directory)]})
    with pytest.raises(ValueError):
        business.snapshot("operador")
    store.set("config", {"roots": [str(root), str(root / "subpasta")]})
    with pytest.raises(ValueError):
        business.snapshot("operador")


def test_selected_symlink_is_rejected(setup):
    _, root, business = setup
    try:
        (root / "link").symlink_to(root / "documento.txt")
    except OSError:
        pytest.skip("Criação de symlink indisponível para esta conta no Windows.")
    with pytest.raises(ValueError, match="Links"):
        business.snapshot("operador")
    assert business.summary()["packs"] == []


@pytest.mark.parametrize("name", ["/absolute", "../outside", "pasta/../outside", "pasta\\outside", "C:/outside", "pasta//arquivo"])
def test_restore_names_cannot_escape_new_directory(name):
    with pytest.raises(ValueError):
        safe_name(name)


def test_stopped_or_incomplete_monitor_stays_unknown(setup):
    store, _, business = setup
    store.set("heartbeat", {"running": False, "stopped_at": "2026-01-01T00:00:00Z"})
    assert status(business, "monitor") == "unknown"
    assert status(business, "pending") == "unknown"


def test_api_session_csrf_and_real_recovery_are_required(setup):
    store, root, _ = setup
    server = OperationsServer(store, 0, monitor=Monitor(store, system="Darwin"))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def request(path, body=None, auth=None, origin=None):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
        headers = {"Origin": origin or f"http://127.0.0.1:{server.server_port}", **(auth or {})}
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn.request("POST" if body is not None else "GET", path, json.dumps(body) if body is not None else None, headers)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    try:
        assert request("/api/business")[0] == 401
        assert request("/api/business/snapshot", {})[0] == 401
        code, headers, body = request("/api/login", {"username": "operador", "password": PASSWORD})
        assert code == 200
        auth = {"Cookie": headers["Set-Cookie"].split(";")[0], "X-NetGuard-CSRF": json.loads(body)["csrf"]}
        assert request("/api/business")[0] == 401
        assert request("/api/business", auth=auth)[0] == 200
        assert request("/api/business/snapshot", {}, {"Cookie": auth["Cookie"]})[0] == 403
        assert request("/api/business/snapshot", {}, auth, "https://evil.test")[0] == 403
        code, _, body = request("/api/business/snapshot", {}, auth)
        assert code == 200, body.decode("utf-8")
        identifier = json.loads(body)["id"]
        code, _, body = request("/api/business/restore", {"id": identifier}, auth)
        assert code == 200 and json.loads(body)["status"] == "verified"
        assert (root / "documento.txt").read_bytes() == b"trabalho ficticio v1"
        assert request("/api/business/restore", {"id": "../../outside"}, auth)[0] == 400
        assert request("/api/business/restore", {"id": identifier, "path": "/tmp"}, auth)[0] == 400
        assert request("/index.html")[0] == 200
        assert request("/continuity-views.js")[0] == 200
        assert request("/api/logout", {}, auth)[0] == 200
        assert request("/api/business", auth=auth)[0] == 401
        with store.db() as db:
            assert PASSWORD not in str([dict(r) for r in db.execute("SELECT * FROM audit")])
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=10)


def test_pack_digest_corresponds_to_actual_zip(setup):
    _, _, business = setup
    pack = business.snapshot("operador")
    assert hashlib.sha256((business.packs / (pack["id"] + ".zip")).read_bytes()).hexdigest() == pack["sha256"]


def test_changed_scope_invalidates_previous_success(setup, tmp_path):
    store, _, business = setup
    pack = business.snapshot("operador")
    business.restore(pack["id"], "operador")
    other = tmp_path / "other"
    other.mkdir()
    (other / "new.txt").write_text("Outro escopo de teste")
    store.set("config", {"roots": [str(other)]})
    control = next(c for c in business.summary()["controls"] if c["id"] == "backup")
    assert control["scope_matches"] is False and control["status"] == "attention"


def test_investigation_remains_pending_until_recognized_and_incident_is_visible(setup):
    store, _, business = setup
    event = store.add_event("file_modified", "Alteração observada", "test")
    assert business.summary()["pending_events"] == 1
    store.decide(event, "investigate", "Falta validar esta alteração com a pessoa responsável.", "operador")
    assert business.summary()["pending_events"] == 1
    store.decide(event, "incident", "Responsável classificou como incidente para acompanhamento.", "operador")
    assert status(business, "pending") == "critical"
    store.decide(event, "recognized", "Mudança autorizada e validada com evidência no serviço.", "operador")
    assert business.summary()["pending_events"] == 0


def test_successful_review_expires_but_critical_issue_does_not_disappear(setup):
    store, _, business = setup
    business.review("access", "reviewed", "Pessoa", "Revisão concluída na fonte e com contexto de teste.", "operador")
    business.review("remote", "critical", "Pessoa", "Acesso não previsto exige intervenção autorizada de TI.", "operador")
    later = Business(store, clock=lambda: datetime.now(timezone.utc) + timedelta(days=31))
    assert status(later, "access") == "unknown"
    assert status(later, "remote") == "critical"


def test_windows_file_times_are_compared_within_each_stat_api_without_ignoring_changes():
    def sample(**changes):
        return SimpleNamespace(**{"st_dev": 1, "st_ino": 7, "st_size": 12,
                                  "st_mtime_ns": 1000000123, "st_ctime_ns": 3000000123, **changes})
    by_path = sample()
    by_handle = sample(st_mtime_ns=1000000100, st_ctime_ns=3000000100)
    assert stable_read(by_path, by_handle, by_handle, by_path, 12, windows=True)
    assert not stable_read(by_path, by_handle, sample(st_mtime_ns=2000000000), by_path, 12, windows=True)
    assert not stable_read(by_path, by_handle, by_handle, sample(st_ino=99), 12, windows=True)
    assert not stable_read(by_path, by_handle, by_handle, sample(st_mtime_ns=2000000000), 12, windows=True)
    assert not stable_read(by_path, by_handle, by_handle, by_path, 11, windows=True)
    assert not stable_read(by_path, by_path, sample(st_ctime_ns=4000000123), by_path, 12, windows=False)
