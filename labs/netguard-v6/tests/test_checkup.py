import json
from datetime import datetime
from pathlib import Path

import pytest

from netguard.checkup import (
    IDS, PS, Unavailable, assess_windows, check, collect_linux, collect_windows,
    compare_reports, load_report, make_report, private_write, report_html, validate_report,
)

DEVICE = "314f9fdd-6285-4cb6-8394-a41a9f7abdd1"


def fixture_report(stamp="2026-10-10T10:00:00Z"):
    now = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    checks = [check(k, "unknown", "Sem coleta.", "Consulta local", "Cobertura desconhecida.") for k in IDS]
    return make_report(DEVICE, "PC de teste", system="Windows", checks=checks, now=now)


def test_windows_firewall_requires_all_profiles_and_effective_default():
    data = [{"name": n, "enabled": "True", "inbound": "Block"} for n in ("Domain", "Private", "Public")]
    assert assess_windows("firewall", data)["status"] == "green"
    data[0]["inbound"] = "NotConfigured"
    assert assess_windows("firewall", data)["status"] == "yellow"
    for c in data:
        c["enabled"] = "False"
    assert assess_windows("firewall", data)["status"] == "red"
    with pytest.raises(Unavailable):
        assess_windows("firewall", data[:2])
    assert "ActiveStore" in PS["firewall"]


def test_antimalware_passive_and_missing_values_never_green():
    result = assess_windows("antimalware", {"AMRunningMode": "Passive Mode", "RealTimeProtectionEnabled": False})
    assert result["status"] == "yellow"
    data = {"AMRunningMode": "Normal", "RealTimeProtectionEnabled": False, "AntivirusEnabled": True, "AntivirusSignatureAge": 1}
    assert assess_windows("antimalware", data)["status"] == "red"
    data["RealTimeProtectionEnabled"] = True
    assert assess_windows("antimalware", data)["status"] == "green"
    data["AntivirusSignatureAge"] = 8
    assert assess_windows("antimalware", data)["status"] == "yellow"


def test_tcp_listener_does_not_claim_remote_exposure_or_export_addresses():
    data = [{"LocalAddress": "127.0.0.1", "LocalPort": 3389}, {"LocalAddress": "::1", "LocalPort": 445}]
    assert assess_windows("listeners", data)["status"] == "green"
    data.append({"LocalAddress": "0.0.0.0", "LocalPort": 3389})
    result = assess_windows("listeners", data)
    assert result["status"] == "yellow"
    assert "3389" in result["evidence"] and "0.0.0.0" not in result["evidence"]
    assert "não prova" in result["limit"]


def test_windows_failure_is_unknown_and_does_not_leak_error_details():
    def bad(_):
        raise ValueError("account secret@example.test")
    checks = collect_windows(bad)
    assert len(checks) == 6 and all(c["status"] == "unknown" for c in checks)
    assert "secret" not in json.dumps(checks)


def test_linux_real_proc_formats_and_journal_redaction(monkeypatch):
    monkeypatch.setattr("netguard.checkup.shutil.which", lambda x: "/usr/bin/"+x if x == "journalctl" else None)
    files = {
        "/proc/net/tcp": "head\n0: 00000000:0D3D 00000000:0000 0A more\n1: 0100007F:01BD 00000000:0000 0A more",
        "/proc/net/tcp6": "head\n0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A more",
        "/proc/net/route": "head\neth0 00000000 01010101 0003",
        "/etc/resolv.conf": "nameserver 127.0.0.53\n",
    }
    def runner(argv):
        assert argv[-1] == "_COMM=sshd"
        return json.dumps({"MESSAGE": "Failed password for private-user from 192.0.2.44"})
    results = {c["id"]: c for c in collect_linux(runner, files.__getitem__)}
    assert results["listeners"]["status"] == "yellow"
    assert results["network"]["status"] == "green"
    assert results["antimalware"]["status"] == "unknown"
    assert "1 falha" in results["authlogs"]["evidence"]
    assert "private-user" not in json.dumps(results)
    assert "192.0.2.44" not in json.dumps(results)


def test_linux_missing_sources_and_empty_journal_not_green(monkeypatch):
    monkeypatch.setattr("netguard.checkup.shutil.which", lambda x: "/usr/bin/journalctl" if x == "journalctl" else None)
    def missing(_):
        raise OSError("Denied")
    results = collect_linux(lambda _: "", missing)
    assert all(c["status"] == "unknown" for c in results)


def test_contract_rejects_duplicates_missing_checks_and_invalid_time(tmp_path):
    r = fixture_report()
    validate_report(r)
    r["created_at"] = "2026-02-30T10:00:00Z"
    with pytest.raises(ValueError):
        validate_report(r)
    path = tmp_path / "bad.json"
    path.write_text('{"format":"a","format":"b"}')
    with pytest.raises(ValueError, match="repetida"):
        load_report(path)
    r = fixture_report()
    r["checks"].pop()
    with pytest.raises(ValueError):
        validate_report(r)


def test_comparison_requires_same_device_order_and_keeps_unknown():
    before = fixture_report("2026-10-09T10:00:00Z")
    after = fixture_report()
    after["checks"][0]["status"] = "green"
    assert compare_reports(before, after)[0] == {"id":"firewall", "before":"unknown", "after":"green"}
    with pytest.raises(ValueError):
        compare_reports(after, before)
    after["device_id"] = "314f9fdd-6285-4cb6-8394-a41a9f7abdd2"
    with pytest.raises(ValueError):
        compare_reports(before, after)


def test_offline_html_escapes_alias_and_source():
    r = fixture_report()
    r["device_alias"] = '<img src=x onerror="alert(1)">'
    r["checks"][0]["evidence"] = "<script>danger</script>"
    rendered = report_html(r)
    assert "<script>danger" not in rendered
    assert "&lt;script&gt;danger" in rendered
    assert "&lt;img" in rendered
    assert "default-src 'none'" in rendered


def test_private_files_are_exclusive_and_symlinks_rejected(tmp_path):
    file = tmp_path / "result.json"
    private_write(file, "a")
    with pytest.raises(FileExistsError):
        private_write(file, "b")
    private_write(file, "b", replace=True)
    assert file.read_text() == "b"
    link = tmp_path / "linked.json"
    link.symlink_to(file)
    with pytest.raises(ValueError):
        private_write(link, "oops", replace=True)
    assert file.read_text() == "b"


def test_cli_daily_prevents_second_collection_and_validation(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("collector_cli", Path(__file__).parents[1]/"netguard_checkup.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    directory = tmp_path / "private"
    assert cli.main(["--directory", str(directory), "--daily"]) == 0
    files = list(directory.glob("checkup-*.json"))
    assert len(files) == 1
    assert cli.main(["--directory", str(directory), "--daily"]) == 0
    assert len(list(directory.glob("checkup-*.json"))) == 1
    assert cli.main(["--validate", str(files[0])]) == 0
    bundle = json.loads((directory / "historico.json").read_text())
    assert len(bundle["reports"]) == 1 and bundle["format"] == "netguard-history"
