"""Fronteiras e comportamento observado; nenhuma variante vulnerável é servida em HTTP."""
import http.client
import json
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"src"))

from empresa_viva.helpdesk import Helpdesk
from empresa_viva.reports import authentication_csv, report_html
from empresa_viva.scenarios import MISSION_IDS, catalog, compare
from empresa_viva.security import Denied, LoginBudget, Sessions, password_hash
from empresa_viva.server import Server
from empresa_viva.store import Store

TEST_PASSWORD = "FIXTURE-ONLY-not-a-live-password-2026"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hashes = {k: password_hash(TEST_PASSWORD) for k in ("lia", "rafa", "admin")}

    def setUp(self):
        self.store = Store()
        self.store.initialize({k: TEST_PASSWORD for k in self.hashes}, hashes=self.hashes)
        self.app = Helpdesk(self.store)

    def tearDown(self):
        self.store.close()

    def identity(self, name):
        return self.store.identity(self.store.user(name))

    def denied(self, status, fn, *args):
        with self.assertRaises(Denied) as error:
            fn(*args)
        self.assertEqual(error.exception.status, status)


class TestHelpdesk(Base):
    def test_owner_other_anonymous_admin_read_boundaries(self):
        self.denied(401, self.app.get_ticket, None, 202)
        self.assertEqual(self.app.get_ticket(self.identity("rafa"), 202)["owner"], "rafa")
        self.denied(404, self.app.get_ticket, self.identity("lia"), 202)
        self.assertEqual(self.app.get_ticket(self.identity("admin"), 202)["id"], 202)
        self.denied(404, self.app.get_ticket, self.identity("lia"), 999)

    def test_creation_uses_identity_and_validates_input(self):
        created = self.app.create_ticket(self.identity("lia"), "Serviço fictício", "Descrição fictícia para estudar autorização.")
        self.assertEqual(created["owner"], "lia")
        self.denied(404, self.app.get_ticket, self.identity("rafa"), created["id"])
        self.denied(400, self.app.create_ticket, self.identity("lia"), "x", "short")

    def test_admin_action_denies_customer_before_mutation(self):
        self.denied(401, self.app.close_ticket, None, 101)
        self.denied(403, self.app.close_ticket, self.identity("rafa"), 101)
        self.assertEqual(self.app.get_ticket(self.identity("lia"), 101)["status"], "open")
        self.assertEqual(self.app.close_ticket(self.identity("admin"), 101)["status"], "closed")

    def test_ids_are_not_coerced_from_bool_float_or_sql(self):
        for value in (True, -1, 0, 1.0, "101 OR 1=1", 2**40):
            with self.subTest(value=value):
                self.denied(400, self.app.get_ticket, self.identity("lia"), value)

    def test_sessions_logout_expiry_and_tokens_not_in_events(self):
        clock = [0]
        self.app = Helpdesk(self.store, clock=lambda: clock[0])
        value, token = self.app.login("lia", TEST_PASSWORD)
        self.assertNotIn(token, self.app.sessions.values)
        self.assertEqual(self.app.session(token)["identity"].id, "lia")
        self.app.logout(token)
        self.denied(401, self.app.session, token)
        _, second = self.app.login("lia", TEST_PASSWORD)
        clock[0] = 901
        self.denied(401, self.app.session, second)
        serialized = json.dumps(self.store.events(self.identity("admin")))
        for secret in (TEST_PASSWORD, token, second, value["csrf"]):
            self.assertNotIn(secret, serialized)

    def test_absolute_session_expiry_with_continued_activity(self):
        clock = [0]
        sessions = Sessions(lambda: clock[0])
        token, _ = sessions.create(self.identity("lia"))
        for _ in range(16):
            clock[0] += 850
            sessions.get(token)
        clock[0] = 14401
        self.denied(401, sessions.get, token)

    def test_limit_is_temporary_does_not_extend_and_other_source_survives(self):
        clock = [0]
        budget = LoginBudget(lambda: clock[0])
        for _ in range(5):
            self.assertTrue(budget.allow("192.0.2.50", "rafa"))
        for second in (10, 20, 59):
            clock[0] = second
            self.assertFalse(budget.allow("192.0.2.50", "rafa"))
        self.assertTrue(budget.allow("192.0.2.60", "rafa"))
        clock[0] = 60
        self.assertTrue(budget.allow("192.0.2.50", "rafa"))

    def test_events_visible_only_to_actor_or_admin(self):
        self.app.get_ticket(self.identity("lia"), 101)
        self.app.get_ticket(self.identity("rafa"), 202)
        self.assertTrue(all(e["actor"] == "lia" for e in self.store.events(self.identity("lia"))))
        self.assertEqual({e["actor"] for e in self.store.events(self.identity("admin"))}, {"lia", "rafa"})


class TestScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runs = {m: compare(m) for m in MISSION_IDS}

    def test_all_known_cases_match_their_declared_behaviors(self):
        for mission, run in self.runs.items():
            with self.subTest(mission=mission):
                self.assertEqual(run["mode"], "observed_python")
                self.assertTrue(all(c["passed"] for c in run["checks"]))
                self.assertTrue(all(p["operations"] <= p["budget"] for p in run["variants"]))
                self.assertEqual({e["run_id"] for p in run["variants"] for e in p["events"]}, {run["id"]})
        before, after = self.runs["ownership"]["variants"]
        self.assertEqual(next(e["status"] for e in before["events"] if e["reason"] == "Outro cliente consulta"), 200)
        self.assertEqual(next(e["status"] for e in after["events"] if e["reason"] == "Outro cliente consulta"), 404)

    def test_benign_login_and_derived_alert_are_distinct(self):
        events = self.runs["login"]["variants"][1]["events"]
        self.assertEqual([e["status"] for e in events if e["actor"] == "lia"], [401, 401, 200])
        alert = next(e for e in events if e["origin"] == "derived")
        self.assertIn("não prova", alert["reason"])
        self.assertEqual(next(e["source_ip"] for e in events if e["reason"].startswith("Outra origem")), "192.0.2.60")

    def test_transfer_changes_resource_and_checks_remain_valid(self):
        for m in MISSION_IDS:
            with self.subTest(mission=m):
                run = compare(m, transfer=True)
                self.assertTrue(all(c["passed"] for c in run["checks"]))
                self.assertEqual(run["exercise"], "transfer")
                if m in {"ownership", "admin"}:
                    self.assertIn("707", {e["resource"] for p in run["variants"] for e in p["events"]})

    def test_episode_reset_is_new_identity_and_does_not_reuse_evidence(self):
        first, second = self.runs["ownership"], compare("ownership")
        self.assertNotEqual(first["id"], second["id"])
        a = {e["id"] for p in first["variants"] for e in p["events"]}
        b = {e["id"] for p in second["variants"] for e in p["events"]}
        self.assertFalse(a & b)
        self.assertEqual(first["configuration"], second["configuration"])

    def test_scenarios_have_no_network_or_shell_capability(self):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network not allowed")), \
             patch("subprocess.run", side_effect=AssertionError("shell not allowed")):
            result = compare("ownership")
            self.assertTrue(all(c["passed"] for c in result["checks"]))
        for m in ("https://example.com", "127.0.0.1", "whoami"):
            with self.assertRaises(Denied):
                compare(m)

    def test_no_cookie_csrf_or_password_is_serialized_in_run(self):
        for run in self.runs.values():
            def keys(value):
                if isinstance(value, dict):
                    for k, v in value.items():
                        self.assertNotIn(k.lower(), {"password", "token", "csrf", "cookie", "authorization", "password_hash"})
                        keys(v)
                elif isinstance(value, list):
                    for v in value:
                        keys(v)
            keys(run)

    def test_catalog_has_original_missions_and_explicit_planned_trails(self):
        data = catalog()
        self.assertEqual([m["id"] for m in data["missions"]], list(MISSION_IDS))
        self.assertTrue(all(len(m["hints"]) == 3 for m in data["missions"]))
        self.assertTrue(all(t["status"] in {"planned", "partly_implemented"} for t in data["roadmap"]))

    def test_csv_is_compatible_with_existing_netguard_parser(self):
        from netguard.logs import analyze_auth_csv
        # Parser público anterior: CSV é só de autenticação da variante corrigida.
        text = authentication_csv(self.runs["login"])
        self.assertTrue(text.startswith("timestamp,usuario,ip,resultado"))
        self.assertTrue(analyze_auth_csv(text.encode()))


class TestReports(Base):
    def test_report_ownership_evidence_binding_and_html_escape(self):
        run = TestScenarios.runs.get("ownership") if hasattr(TestScenarios, "runs") else compare("ownership")
        self.store.save_run("lia", run)
        self.denied(404, self.store.run, "rafa", run["id"])
        payload = {"run_id": run["id"], "evidence_ids": [run["variants"][0]["events"][0]["id"]],
                   **{k: '<script>alert("xss")</script> descrição fictícia de evidência.' for k in ("observation", "alternative", "correction", "limits", "next_step")}, "conclusion": "suspected"}
        report = self.store.save_report("lia", payload)
        self.assertEqual(self.store.reports("rafa"), [])
        self.assertNotIn("<script>", report_html(report, run))
        self.assertIn("&lt;script&gt;", report_html(report, run))
        payload["evidence_ids"] = ["a"*32]
        self.denied(400, self.store.save_report, "lia", payload)


class TestHTTP(Base):
    def setUp(self):
        super().setUp()
        self.server = Server(self.store, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        super().tearDown()

    def request(self, path, payload=None, headers=None, raw=None):
        values = {"Origin": self.server.origin}
        values.update(headers or {})
        body = raw if raw is not None else json.dumps(payload) if payload is not None else None
        if body is not None:
            values["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=20)
        conn.request("POST" if body is not None else "GET", path, body, values)
        reply = conn.getresponse()
        result = reply.status, dict(reply.getheaders()), reply.read()
        conn.close()
        return result

    def credentials(self, username):
        status, headers, data = self.request("/api/login", {"username": username, "password": TEST_PASSWORD})
        self.assertEqual(status, 200)
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        return {"Cookie": headers["Set-Cookie"].split(";")[0], "X-NetGuard-CSRF": json.loads(data)["csrf"]}

    def test_direct_http_owner_and_admin_permissions_are_server_checks(self):
        self.assertEqual(self.request("/api/tickets/202")[0], 401)
        lia, rafa, admin = (self.credentials(k) for k in ("lia", "rafa", "admin"))
        self.assertEqual(self.request("/api/tickets/202", headers=rafa)[0], 200)
        self.assertEqual(self.request("/api/tickets/202", headers=lia)[0], 404)
        self.assertEqual(self.request("/api/admin/tickets/101/close", {}, lia)[0], 403)
        self.assertEqual(self.request("/api/admin/tickets/101/close", {}, admin)[0], 200)
        self.assertEqual(self.request("/api/tickets", {"title": "Teste", "body": "Descrição fictícia", "owner": "rafa"}, lia)[0], 400)

    def test_csrf_host_origin_logout_and_malformed_json(self):
        auth = self.credentials("lia")
        self.assertEqual(self.request("/api/tickets", {"title": "Teste", "body": "Descrição fictícia"}, {"Cookie": auth["Cookie"]})[0], 403)
        self.assertEqual(self.request("/api/login", {"username": "lia", "password": TEST_PASSWORD}, {"Origin": "https://other.test"})[0], 403)
        self.assertEqual(self.request("/api/health", headers={"Host": "other.test"})[0], 403)
        self.assertEqual(self.request("/api/login", raw='{"username":"lia","username":"admin","password":"x"}')[0], 400)
        self.assertEqual(self.request("/api/login", raw='{"username":NaN,"password":"x"}')[0], 400)
        self.assertEqual(self.request("/api/logout", {}, auth)[0], 200)
        self.assertEqual(self.request("/api/tickets", headers=auth)[0], 401)

    def test_unknown_target_and_unsafe_variant_routes_are_unavailable(self):
        auth = self.credentials("lia")
        for path in ("/api/vulnerable", "/api/variant/before", "/empresa_viva/lessons.py", "/cyberlab.sqlite3"):
            self.assertEqual(self.request(path, headers=auth)[0], 404)
        self.assertEqual(self.request("/api/runs", {"mission_id": "https://example.com", "transfer": False}, auth)[0], 400)
        self.assertEqual(self.request("/api/runs", {"mission_id": "ownership", "transfer": False, "target": "example.com"}, auth)[0], 400)
        self.assertEqual(self.request("/%2e%2e/README.md", headers=auth)[0], 400)

    def test_protected_download_is_json_and_cannot_cross_owner(self):
        lia, rafa = self.credentials("lia"), self.credentials("rafa")
        status, _, raw = self.request("/api/runs", {"mission_id": "ownership", "transfer": False}, lia)
        self.assertEqual(status, 201)
        run = json.loads(raw)
        path = "/api/runs/"+run["id"]+"/json"
        status, headers, body = self.request(path, headers=lia)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["id"], run["id"])
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertEqual(self.request(path, headers=rafa)[0], 404)
        self.assertEqual(self.request(path)[0], 401)

    def test_static_page_and_modules_have_headers_without_exposing_code(self):
        status, headers, data = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"empresa-viva.js", data)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("/empresa-viva.js")[0], 200)
        self.assertEqual(self.request("/data/empresa-viva-missions.json")[0], 200)
        self.assertEqual(self.request("/api/events")[0], 401)
        self.assertEqual(self.request("/estudos.html")[0], 200)
        self.assertEqual(self.request("/data/controls.json")[0], 200)
        self.assertEqual(self.request("/empresa-viva-books.js")[0], 200)

    def test_book_episodes_are_fixed_private_and_do_not_change_portal_tickets(self):
        lia, rafa = self.credentials("lia"), self.credentials("rafa")
        initial = self.request("/api/tickets", headers=lia)[2]
        for mission in ("permissions", "sql", "xss", "integrity", "response", "attribution"):
            status, _, body = self.request("/api/runs", {"mission_id": mission, "transfer": False}, lia)
            self.assertEqual(status, 201, mission)
            run = json.loads(body)
            self.assertTrue(all(check["passed"] for check in run["checks"]))
            self.assertEqual(self.request("/api/runs/"+run["id"], headers=rafa)[0], 404)
        self.assertEqual(self.request("/api/tickets", headers=lia)[2], initial)
        self.assertEqual(self.request("/api/runs", {"mission_id": [], "transfer": False}, lia)[0], 400)
        self.assertEqual(self.request("/api/search", headers=lia)[0], 404)
        self.assertEqual(self.request("/api/search?q=anything", headers=lia)[0], 400)


class TestCLI(unittest.TestCase):
    def test_init_refuses_fallback_that_could_echo_password(self):
        import getpass
        from netguard_empresa_viva import main
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path).resolve()/"owned-lab"
            with patch("getpass.getpass", side_effect=getpass.GetPassWarning("unsafe echo")), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(main(["--data-dir", str(directory), "init"]), 2)
            store = Store(directory)
            self.assertFalse(store.initialized())
            store.close()

    def test_init_is_reproducible_private_and_does_not_overwrite(self):
        from netguard_empresa_viva import main
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path).resolve()/"owned-lab"
            out, err = StringIO(), StringIO()
            with patch("getpass.getpass", return_value=TEST_PASSWORD), redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(main(["--data-dir", str(directory), "init"]), 0)
                self.assertEqual(main(["--data-dir", str(directory), "init"]), 2)
            self.assertNotIn(TEST_PASSWORD, out.getvalue()+err.getvalue())
            store = Store(directory)
            self.assertEqual({r[0] for r in store.connection.execute("SELECT id FROM users")}, {"lia", "rafa", "admin"})
            self.assertTrue(store.initialized())
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM tickets").fetchone()[0], 2)
            store.close()


if __name__ == "__main__":
    unittest.main()
