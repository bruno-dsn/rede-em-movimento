import hashlib
import http.client
import json
import os
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from netguard.checkup import Unavailable
from netguard.operations_containment import Containment, firewall_script, peer_target
from netguard.operations_monitor import Monitor, read_file, windows_auth_script
from netguard.operations_server import APIError, Auth, OperationsServer
from netguard.operations_store import Store, password_hash, password_matches

PASSWORD = "senha-longa-de-teste-123"


@pytest.fixture
def store(tmp_path):
    result = Store(tmp_path/"state")
    result.init_user("operador", PASSWORD)
    result.set("config", {"roots": [], "interval": 30, "snapshot_files": False, "auto_backup": False})
    return result


def event(store, **kwargs):
    return store.add_event("auth_success", "Logon observado", "test-source", ip="198.51.100.27", **kwargs)


def test_password_unique_salt_no_plaintext_and_invalid_user_cost(store):
    a, b = password_hash(PASSWORD), password_hash(PASSWORD)
    assert a != b and PASSWORD not in a
    assert password_matches(PASSWORD, a)
    assert not password_matches("incorrect", a)
    assert not store.verify_user("missing", PASSWORD)
    with pytest.raises(ValueError):
        store.init_user("another", PASSWORD)
    with pytest.raises(ValueError):
        password_hash("short")


def test_sessions_expire_rotate_and_password_change_invalidates(store):
    clock = [0]
    auth = Auth(store, clock=lambda: clock[0])
    token, session = auth.login("operador", PASSWORD)
    assert token not in auth.sessions and session["csrf"] != token
    assert auth.session(token)["username"] == "operador"
    clock[0] = 1801
    with pytest.raises(APIError) as ex:
        auth.session(token)
    assert ex.value.status == 401
    token, _ = auth.login("operador", PASSWORD)
    store.change_password("operador", PASSWORD, "outra-senha-longa-123")
    with pytest.raises(APIError):
        auth.session(token)


def test_login_rate_limit_and_audit_never_password(store):
    auth = Auth(store)
    for _ in range(5):
        with pytest.raises(APIError) as ex:
            auth.login("operador", "incorrect-password")
        assert ex.value.status == 401
    with pytest.raises(APIError) as ex:
        auth.login("operador", PASSWORD)
    assert ex.value.status == 429
    with store.db() as db:
        audit = str([dict(r) for r in db.execute("SELECT * FROM audit")])
    assert PASSWORD not in audit and "incorrect-password" not in audit


def test_event_deduplication_chain_and_decisions_preserve_original(store):
    first = event(store, external_key="unique")
    assert event(store, external_key="unique") is None
    original = store.investigation(first)["event"]["event_hash"]
    store.decide(first, "recognized", "Serviço previsto e confirmado com TI.", "operador")
    store.decide(first, "investigate", "Novas evidências precisam ser verificadas.", "operador")
    detail = store.investigation(first)
    assert len(detail["decisions"]) == 2 and detail["event"]["disposition"] == "investigate"
    assert detail["event"]["event_hash"] == original
    assert store.verify_chain()["ok"]
    with store.db() as db:
        db.execute("UPDATE events SET payload=? WHERE id=?", ('{"tampered":true}', first))
    assert store.verify_chain()["first_invalid"] == first


def test_filters_escape_sql_wildcards_and_bound_pages(store):
    for i in range(55):
        store.add_event("file_changed", "Mudança", "test", path=f"pasta/arquivo-{i}")
    special = store.add_event("file_changed", "Mudança", "test", path="pasta/100%_literal")
    assert store.events(search="%_")["events"][0]["id"] == special
    assert store.events(search="' OR 1=1 --")["total"] == 0
    first = store.events()
    assert len(first["events"]) == 50 and first["next_before"]
    second = store.events(before=first["next_before"])
    assert len(second["events"]) == 6
    assert not set(r["id"] for r in first["events"]) & set(r["id"] for r in second["events"])


def test_real_file_baseline_small_change_same_mtime_copy_and_absence(store, tmp_path):
    root = tmp_path/"authorized"
    root.mkdir()
    file = root/"service.py"
    file.write_bytes(b"known service")
    store.set("config", {"roots": [str(root)], "snapshot_files": True})
    monitor = Monitor(store, system="Darwin")
    monitor.scan_files()
    assert [r["kind"] for r in store.events()["events"]] == ["baseline"]
    old_stamp = file.stat().st_mtime_ns
    file.write_bytes(b"changed code!")
    os.utime(file, ns=(old_stamp, old_stamp))
    monitor.scan_files()
    item = store.events(kind="file_changed")["events"][0]
    assert item["metadata"]["sha256"] == hashlib.sha256(b"changed code!").hexdigest()
    assert item["metadata"]["previous_sha256"] == hashlib.sha256(b"known service").hexdigest()
    preserved = store.artifact("versions", item["metadata"]["copy_id"])
    assert preserved.read_bytes() == b"changed code!"
    file.write_bytes(b"another change")
    monitor.scan_files()
    assert preserved.read_bytes() == b"changed code!"
    new_file = root/"new.txt"
    new_file.write_text("new work", encoding="utf-8")
    monitor.scan_files()
    assert store.events(kind="file_appeared")["total"] == 1
    file.unlink()
    monitor.scan_files()
    assert store.events(kind="file_missing")["total"] == 1


def test_incomplete_file_scan_does_not_report_deletion(store, tmp_path, monkeypatch):
    root = tmp_path/"authorized"
    root.mkdir()
    (root/"known.txt").write_text("known", encoding="utf-8")
    store.set("config", {"roots": [str(root)]})
    monitor = Monitor(store)
    monitor.scan_files()
    monkeypatch.setattr("netguard.operations_monitor.MAX_FILES", 0)
    monitor.scan_files()
    assert store.events(kind="file_missing")["total"] == 0
    assert store.summary()["coverage"][0]["status"] == "partial"


@pytest.mark.skipif(os.name == "nt", reason="Symlink pode exigir privilégio no Windows")
def test_links_are_not_read_and_private_modes(store, tmp_path):
    outside = tmp_path/"outside.txt"
    outside.write_text("outside-secret", encoding="utf-8")
    root = tmp_path/"authorized"
    root.mkdir()
    (root/"link.txt").symlink_to(outside)
    store.set("config", {"roots": [str(root)]})
    Monitor(store).scan_files()
    assert store.events(kind="file_appeared")["total"] == 0
    with pytest.raises(ValueError):
        read_file(root/"link.txt")
    assert store.directory.stat().st_mode & 0o777 == 0o700
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_network_records_ip_but_no_invented_direction_and_gaps_keep_state(store, monkeypatch):
    monitor = Monitor(store)
    connection = {"local_ip":"10.0.0.10", "local_port":50000,"ip":"198.51.100.27","port":443,"pid":5}
    monkeypatch.setattr(monitor, "network", lambda: ([connection], False))
    monitor.scan_network()
    item = store.events(kind="network_observed")["events"][0]
    assert item["ip"] == connection["ip"]
    assert item["metadata"]["direction"] == "não determinada"
    monitor.scan_network()
    assert store.events(kind="network_observed")["total"] == 1
    monkeypatch.setattr(monitor, "network", lambda: ([], True))
    monitor.scan_network()
    assert store.events(kind="network_missing")["total"] == 0
    monkeypatch.setattr(monitor, "network", lambda: ([], False))
    monitor.scan_network()
    assert store.events(kind="network_missing")["total"] == 1


def test_windows_audit_events_duplicates_and_limits(store, monkeypatch):
    rows=[{"id":4624,"record":42,"time":"2026-10-10T05:00:00Z","data":{"TargetUserName":"alice","IpAddress":"198.51.100.27","LogonType":"10"}},
          {"id":4672,"record":43,"time":"2026-10-10T05:01:00Z","data":{"SubjectUserName":"SYSTEM"}},
          {"id":4663,"record":44,"time":"2026-10-10T05:02:00Z","data":{"SubjectUserName":"alice","ObjectName":"C:/Financeiro/file.xlsx","AccessMask":"0x1"}}]
    monkeypatch.setattr("netguard.operations_monitor.powershell", lambda *a: {"events":rows,"bounded":True})
    monitor = Monitor(store, system="Windows")
    monitor.scan_auth()
    monitor.scan_auth()
    assert store.events()["total"] == 3
    assert store.events(kind="auth_success")["events"][0]["ip"] == "198.51.100.27"
    assert store.events(kind="privilege")["events"][0]["severity"] != "critical"
    assert "não prova" in store.events(kind="object_access")["events"][0]["metadata"]["limit"]
    with pytest.raises(ValueError):
        windows_auth_script("malicious';command")


def test_linux_ssh_extracts_fields_without_raw_message(store, monkeypatch):
    message="Accepted publickey for alice from 198.51.100.27 port 51111 ssh2 private-trailing-token"
    monkeypatch.setattr("netguard.operations_monitor.shutil.which",lambda _:"/usr/bin/journalctl")
    row={"MESSAGE":message,"__REALTIME_TIMESTAMP":"1791608400000000"}
    Monitor(store, system="Linux", runner=lambda _:json.dumps(row)).scan_auth()
    item = store.events()["events"][0]
    assert item["ip"] == "198.51.100.27" and item["account"] == "alice"
    with store.db() as db:
        content = str([dict(r) for r in db.execute("SELECT * FROM events")])
    assert "private-trailing-token" not in content


def test_backup_hash_manifest_copies_and_no_credentials(store):
    data=b"preserved code"
    identifier=store.capture(data,hashlib.sha256(data).hexdigest())
    store.add_event("file_changed","Mudança","test",metadata={"copy_id":identifier})
    info=store.backup("operador")
    file=store.artifact("backups",info["id"])
    assert hashlib.sha256(file.read_bytes()).hexdigest() == info["sha256"]
    with zipfile.ZipFile(file) as archive:
        manifest=json.loads(archive.read("manifest.json"))
        for name,digest in manifest["files"].items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
        assert archive.read("copies/"+identifier+".bin") == data
        content=b"".join(archive.read(name) for name in archive.namelist())
        assert PASSWORD.encode() not in content and b"pbkdf2-sha256" not in content
    with pytest.raises(ValueError):
        store.artifact("versions","../../file")


@pytest.mark.parametrize("value",["127.0.0.1","::1","0.0.0.0","169.254.1.2","224.0.0.1","1.2.3.4';command"])
def test_containment_rejects_unsafe_targets(value):
    with pytest.raises(ValueError):
        peer_target(value)


def test_containment_is_manual_disabled_by_default_and_cancel_preserves_plan(store):
    identifier=event(store)
    adapter=Containment(store)
    plan=adapter.plan(identifier,"peer","operador")
    with pytest.raises(ValueError,match="desabilitado"):
        adapter.apply(plan["id"],"operador",PASSWORD,"APLICAR",True)
    assert adapter.record(plan["id"])["status"] == "planned"
    adapter.cancel(plan["id"],"operador")
    assert adapter.record(plan["id"])["status"] == "cancelled"


def test_containment_stepup_case_confirmation_namespace_and_release(store, monkeypatch):
    identifier=event(store)
    adapter=Containment(store,enabled=True,system="Windows")
    plan=adapter.plan(identifier,"isolate","operador")
    scripts=[]
    def execute(script,*_):
        scripts.append(script)
        return {"released":True} if "released=$true" in script else {"rules":2}
    monkeypatch.setattr("netguard.operations_containment.powershell",execute)
    confirmation=adapter.capabilities()["confirmation"]
    with pytest.raises(ValueError,match="Incidente"):
        adapter.apply(plan["id"],"operador",PASSWORD,confirmation,True)
    store.decide(identifier,"incident","Incidente confirmado em laboratório autorizado.","operador")
    for password,confirm,ack in [("wrong-password",confirmation,True),(PASSWORD,"wrong",True),(PASSWORD,confirmation,False)]:
        with pytest.raises(ValueError):
            adapter.apply(plan["id"],"operador",password,confirm,ack)
    assert not scripts
    assert adapter.apply(plan["id"],"operador",PASSWORD,confirmation,True)["status"] == "applied_unverified"
    assert "-RemoteAddress 'Any'" in scripts[0] and "-Direction Inbound" in scripts[0] and "-Direction Outbound" in scripts[0]
    assert "NetGuard Operations" in scripts[0] and "Get-NetFirewallProfile -PolicyStore ActiveStore" in scripts[0]
    assert adapter.release(plan["id"],"operador",PASSWORD,"Causa corrigida e recuperação validada com o responsável.")["status"] == "released"
    assert "Remove-NetFirewallRule" in scripts[-1] and plan["id"] in scripts[-1]
    with pytest.raises(ValueError):
        firewall_script("injection","peer","198.51.100.27")


def test_containment_failure_remains_reviewable(store, monkeypatch):
    identifier=event(store)
    store.decide(identifier,"incident","Incidente confirmado neste teste controlado.","operador")
    adapter=Containment(store,enabled=True,system="Windows")
    plan=adapter.plan(identifier,"peer","operador")
    def fail(*_):
        raise Unavailable("failed")
    monkeypatch.setattr("netguard.operations_containment.powershell",fail)
    with pytest.raises(ValueError,match="não confirmada"):
        adapter.apply(plan["id"],"operador",PASSWORD,adapter.capabilities()["confirmation"],True)
    assert adapter.record(plan["id"])["status"] == "failed"


def test_two_containment_requests_cannot_apply_same_plan_twice(store, monkeypatch):
    identifier = event(store)
    store.decide(identifier, "incident", "Incidente confirmado em teste autorizado.", "operador")
    adapter = Containment(store, enabled=True, system="Windows")
    plan = adapter.plan(identifier, "peer", "operador")
    start, entered, finish = threading.Barrier(2), threading.Event(), threading.Event()
    calls = []

    def execute(script, *_):
        calls.append(script)
        entered.set()
        assert finish.wait(timeout=5)
        return {"rules": 2}

    def apply():
        start.wait(timeout=5)
        try:
            return adapter.apply(plan["id"], "operador", PASSWORD, adapter.capabilities()["confirmation"], True)["status"]
        except ValueError:
            return "rejected"

    monkeypatch.setattr("netguard.operations_containment.powershell", execute)
    monkeypatch.setattr(store, "verify_user", lambda *_: True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(apply) for _ in range(2)]
        assert entered.wait(timeout=5)
        finish.set()
        assert sorted(job.result(timeout=5) for job in jobs) == ["applied_unverified", "rejected"]
    assert len(calls) == 1 and adapter.record(plan["id"])["status"] == "applied_unverified"


@pytest.fixture
def service(store):
    server=OperationsServer(store,0,monitor=Monitor(store,system="Darwin"))
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    def request(path,body=None,headers=None,raw=None):
        connection=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=10)
        values={"Origin":f"http://127.0.0.1:{server.server_port}"}
        if headers:
            values.update(headers)
        if body is not None or raw is not None:
            values["Content-Type"]="application/json"
            data=raw if raw is not None else json.dumps(body)
            connection.request("POST",path,data,headers=values)
        else:
            connection.request("GET",path,headers=values)
        response=connection.getresponse()
        content=response.read()
        result=(response.status,dict(response.getheaders()),content)
        connection.close()
        return result
    yield server,request
    server.shutdown()
    server.server_close()
    thread.join(timeout=10)


def credentials(request):
    status,headers,data=request("/api/login",{"username":"operador","password":PASSWORD})
    assert status == 200
    session=json.loads(data)
    assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    return {"Cookie":headers["Set-Cookie"].split(";")[0],"X-NetGuard-CSRF":session["csrf"]}


def test_http_auth_host_origin_csrf_and_logout(service):
    server,request=service
    assert request("/api/health")[0] == 200
    status,_,body=request("/api/dashboard")
    assert status == 401 and b"hostname" not in body
    assert request("/api/health",headers={"Host":"evil.example"})[0] == 403
    assert request("/api/login",{"username":"operador","password":PASSWORD},headers={"Origin":"https://evil.example"})[0] == 403
    auth=credentials(request)
    assert request("/api/dashboard",headers=auth)[0] == 200
    assert request("/api/backups",{},headers={"Cookie":auth["Cookie"]})[0] == 403
    assert request("/api/login",raw='{"username":"operador","username":"evil","password":"x"}')[0] == 400
    assert request("/api/investigations",{"event_id":True,"disposition":"incident","note":"test contextual"},headers=auth)[0] == 400
    status,headers,_=request("/api/logout",{},headers=auth)
    assert status == 200 and "Max-Age=0" in headers["Set-Cookie"]
    assert request("/api/dashboard",headers=auth)[0] == 401
    assert server.server_address[0] == "127.0.0.1"


def test_http_investigation_backup_and_protected_download(service,store):
    _,request=service
    identifier=event(store)
    auth=credentials(request)
    result=request("/api/investigations",{"event_id":identifier,"disposition":"recognized","note":"Atividade prevista e validada com o responsável."},headers=auth)
    assert result[0] == 200 and json.loads(result[2])["event"]["disposition"] == "recognized"
    status,_,data=request("/api/backups",{},headers=auth)
    assert status == 200
    path="/api/backups/"+json.loads(data)["id"]
    assert request(path)[0] == 401
    status,headers,content=request(path,headers=auth)
    assert status == 200 and content.startswith(b"PK")
    assert "attachment" in headers["Content-Disposition"] and headers["X-Content-Type-Options"] == "nosniff"
    assert request("/operations.html")[0] == 200
    assert request("/operations-views.js")[0] == 200
    assert request("/../operations.sqlite3",headers=auth)[0] == 404
    assert request("/tests/test_operations.py",headers=auth)[0] == 404


def test_configuration_rejects_overlaps_state_and_root(store,tmp_path):
    import importlib.util
    spec=importlib.util.spec_from_file_location("operations_cli",Path(__file__).parents[1]/"netguard_operations.py")
    cli=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    root=tmp_path/"authorized"
    root.mkdir()
    args=cli.parser().parse_args(["configure","--watch",str(root),"--interval","10"])
    assert cli.configuration(store,args)["roots"] == [str(root)]
    for paths in [[str(tmp_path)],[str(root),str(root)],[os.path.abspath(os.sep)]]:
        args=cli.parser().parse_args(["configure",*[v for p in paths for v in ("--watch",p)]])
        with pytest.raises(ValueError):
            cli.configuration(store,args)
