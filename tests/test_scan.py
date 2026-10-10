import tempfile
import unittest
from datetime import date
from pathlib import Path

from planguard.scan import Config, ConfigError, Waiver, load_config, scan

from .helpers import make_plan

TODAY = date(2026, 10, 10)


def plan():
    return make_plan(
        ("aws_db_instance", "db", {"publicly_accessible": True, "storage_encrypted": True, "backup_retention_period": 0}),
        ("aws_ebs_volume", "v", {"encrypted": False}),
    )


def waiver(rule="PG006", resource="aws_db_instance.db", expires=date(2027, 1, 1)):
    return Waiver(rule, resource, "Demo database with fake data", expires, owner="primel")


class ScanTest(unittest.TestCase):
    def test_sorted_worst_first(self):
        result = scan(plan(), today=TODAY)
        self.assertEqual([f.rule.id for f in result.findings], ["PG006", "PG008", "PG011"])

    def test_min_severity(self):
        result = scan(plan(), min_severity="high", today=TODAY)
        self.assertEqual([f.rule.id for f in result.findings], ["PG006"])

    def test_cloud_filter(self):
        result = scan(plan(), clouds={"azure"}, today=TODAY)
        self.assertEqual(result.findings, [])

    def test_skip_rules(self):
        result = scan(plan(), Config(skip_rules={"PG011"}), today=TODAY)
        self.assertNotIn("PG011", [f.rule.id for f in result.findings])


class WaiverTest(unittest.TestCase):
    def test_waiver_moves_finding_to_waived(self):
        result = scan(plan(), Config(waivers=[waiver()]), today=TODAY)
        self.assertEqual([f.rule.id for f in result.waived], ["PG006"])
        self.assertNotIn("PG006", [f.rule.id for f in result.active])

    def test_expired_waiver_does_not_apply(self):
        w = waiver(expires=date(2026, 1, 1))
        result = scan(plan(), Config(waivers=[w]), today=TODAY)
        self.assertIn("PG006", [f.rule.id for f in result.active])
        self.assertEqual(result.expired_waivers, [w])

    def test_waiver_on_its_last_day_still_works(self):
        result = scan(plan(), Config(waivers=[waiver(expires=TODAY)]), today=TODAY)
        self.assertEqual(len(result.waived), 1)

    def test_wildcards(self):
        result = scan(plan(), Config(waivers=[waiver(rule="PG0*", resource="*")]), today=TODAY)
        self.assertEqual(result.active, [])

    def test_unused_waiver_is_reported(self):
        w = waiver(resource="aws_db_instance.other")
        result = scan(plan(), Config(waivers=[w]), today=TODAY)
        self.assertEqual(result.unused_waivers, [w])


class LoadConfigTest(unittest.TestCase):
    def write(self, text):
        self.dir = tempfile.TemporaryDirectory()
        path = Path(self.dir.name) / "planguard.toml"
        path.write_text(text)
        return path

    def tearDown(self):
        if hasattr(self, "dir"):
            self.dir.cleanup()

    def test_good_config(self):
        cfg = load_config(self.write('skip_rules = ["PG012"]\n[[waiver]]\nrule = "PG003"\nresource = "x"\nreason = "ok"\nexpires = 2027-01-01\n'))
        self.assertEqual(cfg.skip_rules, {"PG012"})
        self.assertEqual(cfg.waivers[0].expires, date(2027, 1, 1))

    def test_date_as_string(self):
        cfg = load_config(self.write('[[waiver]]\nrule = "PG003"\nresource = "x"\nreason = "ok"\nexpires = "2027-01-01"\n'))
        self.assertEqual(cfg.waivers[0].expires, date(2027, 1, 1))

    def test_waiver_needs_a_reason(self):
        with self.assertRaisesRegex(ConfigError, "missing 'reason'"):
            load_config(self.write('[[waiver]]\nrule = "PG003"\nresource = "x"\nexpires = 2027-01-01\n'))

    def test_waiver_needs_an_end_date(self):
        with self.assertRaisesRegex(ConfigError, "missing 'expires'"):
            load_config(self.write('[[waiver]]\nrule = "PG003"\nresource = "x"\nreason = "ok"\n'))

    def test_bad_date(self):
        with self.assertRaisesRegex(ConfigError, "must be a date"):
            load_config(self.write('[[waiver]]\nrule = "PG003"\nresource = "x"\nreason = "ok"\nexpires = "soon"\n'))

    def test_unknown_rule_in_skip_list(self):
        with self.assertRaisesRegex(ConfigError, "PG999"):
            load_config(self.write('skip_rules = ["PG999"]\n'))

    def test_broken_toml(self):
        with self.assertRaises(ConfigError):
            load_config(self.write("skip_rules = [\n"))


if __name__ == "__main__":
    unittest.main()
