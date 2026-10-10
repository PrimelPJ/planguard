import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import date
from pathlib import Path

from planguard.cli import main
from planguard.plan import load_plan
from planguard.report import to_json, to_markdown, to_sarif, to_text
from planguard.rules import RULES
from planguard.scan import Config, Waiver, scan

EXAMPLES = Path(__file__).parent.parent / "examples"
INSECURE = str(EXAMPLES / "insecure-plan.json")
SECURE = str(EXAMPLES / "secure-plan.json")


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class RuleListTest(unittest.TestCase):
    def test_every_rule_is_filled_in(self):
        for r in RULES:
            self.assertRegex(r.id, r"^PG\d{3}$")
            for text in (r.title, r.risk, r.fix):
                self.assertTrue(text.strip(), r.id)
                self.assertNotIn("\u2014", text, f"{r.id} uses an em dash")
            self.assertTrue(r.controls, r.id)


class ReportTest(unittest.TestCase):
    def setUp(self):
        waiver = Waiver("PG003", "aws_s3_bucket.site", "Rebuilt from git", date(2027, 1, 1), "primel")
        self.result = scan(load_plan(INSECURE), Config(waivers=[waiver]), today=date(2026, 10, 10))

    def test_text(self):
        text = to_text(self.result)
        self.assertIn("Found 21 problems", text)
        self.assertIn("1 waived", text)

    def test_json(self):
        data = json.loads(to_json(self.result))
        self.assertEqual(data["summary"]["problems"], 21)
        self.assertEqual(data["summary"]["critical"], 3)
        self.assertEqual(data["waived"][0]["waiver"]["reason"], "Rebuilt from git")

    def test_sarif(self):
        sarif = json.loads(to_sarif(self.result))
        run = sarif["runs"][0]
        self.assertEqual(sarif["version"], "2.1.0")
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        for res in run["results"]:
            self.assertEqual(rule_ids[res["ruleIndex"]], res["ruleId"])
            self.assertIn("physicalLocation", res["locations"][0])
        suppressed = [r for r in run["results"] if "suppressions" in r]
        self.assertEqual(len(suppressed), 1)

    def test_markdown(self):
        md = to_markdown(self.result, today=date(2026, 10, 10))
        self.assertIn("## NIST SP 800-53 controls", md)
        self.assertIn("| SC-28 | Protection of Information at Rest |", md)
        self.assertIn("Rebuilt from git", md)


class CliTest(unittest.TestCase):
    def test_insecure_plan_fails(self):
        code, out, _ = run("scan", INSECURE)
        self.assertEqual(code, 1)
        self.assertIn("PG004", out)

    def test_secure_plan_passes(self):
        code, out, _ = run("scan", SECURE)
        self.assertEqual(code, 0)
        self.assertIn("No problems found", out)

    def test_fail_on_none(self):
        self.assertEqual(run("scan", INSECURE, "--fail-on", "none")[0], 0)

    def test_fail_on_critical_only(self):
        code, _, _ = run("scan", INSECURE, "--fail-on", "critical", "--cloud", "aws", "--min-severity", "medium")
        self.assertEqual(code, 1)

    def test_bad_file_gives_exit_2(self):
        code, _, err = run("scan", "missing.json")
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_writes_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "out.sarif")
            code, out, _ = run("scan", INSECURE, "-f", "sarif", "-o", target, "--fail-on", "none")
            self.assertEqual(code, 0)
            self.assertIn("Report written", out)
            self.assertEqual(json.loads(Path(target).read_text())["version"], "2.1.0")

    def test_uses_example_config(self):
        code, out, _ = run("scan", INSECURE, "-c", str(EXAMPLES / "planguard.toml"))
        self.assertIn("1 waived", out)

    def test_rules_command(self):
        code, out, _ = run("rules", "--cloud", "azure")
        self.assertEqual(code, 0)
        self.assertIn("PG104", out)
        self.assertNotIn("PG004", out)


if __name__ == "__main__":
    unittest.main()
