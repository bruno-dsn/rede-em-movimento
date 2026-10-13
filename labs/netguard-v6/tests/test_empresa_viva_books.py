"""Invariantes das missões novas: acesso, bytes, contexto e limites de execução."""
import html
import socket
import sqlite3
import unittest
from unittest.mock import patch

from empresa_viva.book_models import (BOOK_MISSIONS, Principal, SearchFixture, classify_change, compare_manifests,
                                     containment_plan, correlate_access, manifest, permission_allowed,
                                     recovery_allowed, render_comment, sha256_bytes)
from empresa_viva.book_scenarios import book_run
from empresa_viva.reports import report_html
from empresa_viva.scenarios import catalog, compare
from empresa_viva.security import Denied


class TestBookControls(unittest.TestCase):
    def test_permissions_select_exactly_one_class_without_fallback(self):
        owner = Principal(11, frozenset({22}))
        group = Principal(12, frozenset({22, 23}))
        outsider = Principal(13, frozenset({23}))
        # Dono sem leitura não herda leitura concedida a grupo/outros.
        self.assertFalse(permission_allowed(0o044, owner, 11, 22))
        self.assertTrue(permission_allowed(0o044, group, 11, 22))
        self.assertTrue(permission_allowed(0o044, outsider, 11, 22))
        # Grupo sem leitura não recorre ao bit de outros.
        self.assertFalse(permission_allowed(0o004, group, 11, 22))
        self.assertTrue(permission_allowed(0o004, outsider, 11, 22))
        for operation, permitted in (("read", True), ("write", False), ("execute", False)):
            self.assertEqual(permission_allowed(0o640, group, 11, 22, operation), permitted)
        for bad in (True, -1, 0o1000, "640"):
            with self.assertRaises(ValueError):
                permission_allowed(bad, owner, 11, 22)

    def test_sql_parameters_preserve_ownership_and_legitimate_apostrophe(self):
        fixture = SearchFixture(transfer=True)
        try:
            for term in ("' OR 1=1 --", "' OR '1'='1"):
                leaked = fixture.search("lia", term, corrected=False)
                self.assertIn(707, {row["id"] for row in leaked})
                self.assertEqual(fixture.search("lia", term), [])
            self.assertEqual(fixture.search("lia", "D'Ávila")[0]["owner"], "lia")
            self.assertEqual(fixture.search("lia", "Financeiro"), [])
            self.assertEqual(fixture.search("rafa", "Financeiro")[0]["id"], 707)
            # O executor não dá capacidade de escrita/attach/extensão às variantes.
            for query in ("DELETE FROM items", "ATTACH DATABASE ':memory:' AS other", "SELECT * FROM sqlite_master"):
                with self.assertRaises(sqlite3.DatabaseError):
                    fixture.db.execute(query)
            self.assertEqual(len(fixture.search("lia", "' OR 1=1 --", corrected=False)), 3)
        finally:
            fixture.close()

    def test_html_text_context_encodes_events_quotes_and_symbols(self):
        for value in ('<img src=x onerror="alert(1)">', '<svg onload="alert(1)"></svg>', "A & B < C ' D\" E"):
            output = render_comment(value)
            self.assertEqual(html.unescape(output), value)
            self.assertNotIn("<", output)
            self.assertNotIn(">", output)
            self.assertEqual(render_comment(value, corrected=False), value)
        with self.assertRaises(ValueError):
            render_comment("x"*513)

    def test_manifest_detects_same_size_change_creation_and_deletion(self):
        old = manifest({"finance.txt": b"100", "removed": b"old"})
        new = manifest({"finance.txt": b"900", "created": b"new"})
        changes = {row["path"]: row for row in compare_manifests(old, new)}
        self.assertEqual(changes["finance.txt"]["kind"], "modified")
        self.assertEqual(changes["created"]["kind"], "created")
        self.assertEqual(changes["removed"]["kind"], "deleted")
        self.assertNotEqual(old["finance.txt"]["sha256"], new["finance.txt"]["sha256"])
        self.assertEqual(old["finance.txt"]["size"], new["finance.txt"]["size"])
        self.assertEqual(classify_change(changes["finance.txt"], {"finance.txt": sha256_bytes(b"100")}), "needs_review")
        self.assertEqual(classify_change(changes["finance.txt"], {"finance.txt": sha256_bytes(b"900")}), "approved_change")

    def test_recovery_requires_each_criterion_and_containment_is_only_a_plan(self):
        ready = dict(evidence_preserved=True, cause_reviewed=True, credentials_rotated=True,
                     restore_verified=True, owner_approved=True)
        self.assertTrue(recovery_allowed(**ready))
        for key in ready:
            self.assertFalse(recovery_allowed(**{**ready, key: False}), key)
        self.assertEqual(containment_plan("finance-server", authorized=False)["state"], "pending_authorization")
        plan = containment_plan("finance-server", authorized=True)
        self.assertEqual(plan["commands_executed"], 0)
        self.assertEqual(plan["internal_network"], "management_path_only")
        with self.assertRaises(ValueError):
            containment_plan("real-company.example", authorized=True)

    def test_attribution_requires_account_resource_and_correlation_and_never_names_person(self):
        event = dict(account="admin", resource="backup", correlation_id="job", source_ip="192.0.2.50")
        approved = {key: event[key] for key in ("account", "resource", "correlation_id")}
        found = correlate_access(event, [approved])
        self.assertEqual(found["classification"], "documented_maintenance")
        self.assertEqual(found["person"], "unknown")
        for key in approved:
            result = correlate_access({**event, key: "different"}, [approved])
            self.assertEqual(result["classification"], "needs_review", key)
            self.assertEqual(result["person"], "unknown")


class TestBookEpisodes(unittest.TestCase):
    def test_executor_does_not_read_user_files_open_network_or_launch_processes(self):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network")), \
             patch("subprocess.run", side_effect=AssertionError("process")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")), \
             patch("builtins.open", side_effect=AssertionError("file")):
            for mission in BOOK_MISSIONS:
                for transfer in (False, True):
                    run = book_run(mission, transfer, "fixture-code-hash")
                    self.assertTrue(all(row["passed"] for row in run["checks"]), mission)
                    self.assertTrue(all(row["operations"] <= row["budget"] for row in run["variants"]))
                    self.assertFalse(run["configuration"]["os_permissions_tested"])
                    self.assertFalse(run["configuration"]["active_html_executed"])
                    self.assertTrue(all(event["status"] is None for part in run["variants"] for event in part["events"]))

    def test_transfer_changes_the_relevant_evidence_in_each_new_mission(self):
        def facts(run):
            return [obs["data"] for part in run["variants"] for obs in part["observations"]]
        for mission in BOOK_MISSIONS:
            first, second = compare(mission), compare(mission, transfer=True)
            # Compare dados observados, sem depender de UUIDs/horários novos.
            self.assertNotEqual(facts(first), facts(second), mission)
            self.assertTrue(all(row["passed"] for row in second["checks"]))

    def test_xss_marker_is_text_in_exported_evidence_report(self):
        run = compare("xss")
        report = {"evidence_ids": [run["variants"][0]["events"][1]["id"]], "conclusion": "suspected",
                  **{key: '<img src=x onerror="alert(1)"> revisão fictícia' for key in
                     ("observation", "alternative", "correction", "limits", "next_step")},
                  "assessment_limit": "Relatório de estudo."}
        output = report_html(report, run)
        self.assertNotIn("<img", output)
        self.assertNotIn("<script", output)
        self.assertIn("&lt;img", output)
        self.assertIn("default-src 'none'", output)

    def test_unknown_or_structured_mission_inputs_are_refused(self):
        for mission in ([], {}, True, None, "../../secret", "https://example.com"):
            with self.assertRaises(Denied):
                compare(mission)
        with self.assertRaises(Denied):
            compare("sql", transfer="false")

    def test_books_are_references_and_all_mission_concepts_have_explanations(self):
        data = catalog()
        self.assertEqual(len(data["missions"]), 9)
        self.assertEqual({book["id"] for book in data["reading"]}, {"kali", "web", "management", "warfare"})
        terms = {term["id"] for term in data["glossary"]}
        for mission in data["missions"]:
            self.assertTrue(set(mission["concepts"]).issubset(terms), mission["id"])
        for book in data["reading"]:
            self.assertTrue(set(book["mission_ids"]).issubset({m["id"] for m in data["missions"]}))


if __name__ == "__main__":
    unittest.main()
