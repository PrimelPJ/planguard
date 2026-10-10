import json
import tempfile
import unittest
from pathlib import Path

from planguard.plan import PlanError, load_plan, parse_plan

from .helpers import make_plan

EXAMPLES = Path(__file__).parent.parent / "examples"


class LoadPlanTest(unittest.TestCase):
    def test_reads_example_plan_with_modules(self):
        plan = load_plan(EXAMPLES / "insecure-plan.json")
        addresses = [r.address for r in plan.resources]
        self.assertIn("aws_s3_bucket.site", addresses)
        self.assertIn("module.storage.azurerm_storage_account.data", addresses)

    def test_module_resources_know_their_module(self):
        plan = load_plan(EXAMPLES / "insecure-plan.json")
        sa = plan.of_type("azurerm_storage_account")[0]
        self.assertEqual(sa.module, "module.storage")

    def test_skips_data_sources(self):
        plan = parse_plan(
            {
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {"address": "data.aws_caller_identity.me", "mode": "data", "type": "aws_caller_identity", "name": "me", "values": {}}
                        ]
                    }
                }
            }
        )
        self.assertEqual(plan.resources, [])

    def test_missing_file(self):
        with self.assertRaisesRegex(PlanError, "not found"):
            load_plan("nope.json")

    def test_bad_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("{not json")
            with self.assertRaisesRegex(PlanError, "not valid JSON"):
                load_plan(p)

    def test_json_that_is_not_a_plan(self):
        with self.assertRaisesRegex(PlanError, "terraform show -json"):
            parse_plan(json.loads('{"hello": "world"}'))


class PointsToTest(unittest.TestCase):
    def test_link_by_config_reference(self):
        # The bucket name is unknown until apply, so only the reference connects them.
        plan = make_plan(
            ("aws_s3_bucket", "a", {}),
            ("aws_s3_bucket_versioning", "a", {}),
            refs={"aws_s3_bucket_versioning.a": {"bucket": ["aws_s3_bucket.a.id", "aws_s3_bucket.a"]}},
        )
        bucket, versioning = plan.resources
        self.assertTrue(versioning.points_to("bucket", bucket))

    def test_link_by_value(self):
        plan = make_plan(("aws_s3_bucket", "a", {"bucket": "my-bucket"}), ("aws_s3_bucket_versioning", "a", {"bucket": "my-bucket"}))
        bucket, versioning = plan.resources
        self.assertTrue(versioning.points_to("bucket", bucket))

    def test_no_link_to_other_bucket(self):
        plan = make_plan(("aws_s3_bucket", "a", {"bucket": "one"}), ("aws_s3_bucket_versioning", "b", {"bucket": "two"}))
        bucket, versioning = plan.resources
        self.assertFalse(versioning.points_to("bucket", bucket))

    def test_similar_name_is_not_a_link(self):
        plan = make_plan(
            ("aws_s3_bucket", "log", {}),
            ("aws_s3_bucket_versioning", "x", {}),
            refs={"aws_s3_bucket_versioning.x": {"bucket": ["aws_s3_bucket.logs.id"]}},
        )
        bucket, versioning = plan.resources
        self.assertFalse(versioning.points_to("bucket", bucket))


if __name__ == "__main__":
    unittest.main()
