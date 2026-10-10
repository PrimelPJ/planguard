import json
import unittest

from .helpers import hits, make_plan

BLOCK_ALL = {"block_public_acls": True, "block_public_policy": True, "ignore_public_acls": True, "restrict_public_buckets": True}
LINK = {"bucket": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}


def sg(*rules):
    return make_plan(("aws_security_group", "sg", {"ingress": list(rules)}))


def ingress(port_from, port_to, cidr="0.0.0.0/0", protocol="tcp"):
    return {"protocol": protocol, "from_port": port_from, "to_port": port_to, "cidr_blocks": [cidr], "ipv6_cidr_blocks": []}


class S3Test(unittest.TestCase):
    def test_public_acl(self):
        self.assertEqual(hits(make_plan(("aws_s3_bucket_acl", "b", {"acl": "public-read"})), "PG001"), ["aws_s3_bucket_acl.b"])
        self.assertEqual(hits(make_plan(("aws_s3_bucket_acl", "b", {"acl": "private"})), "PG001"), [])

    def test_bucket_without_access_block(self):
        self.assertEqual(hits(make_plan(("aws_s3_bucket", "b", {})), "PG002"), ["aws_s3_bucket.b"])

    def test_access_block_with_a_setting_off(self):
        plan = make_plan(
            ("aws_s3_bucket", "b", {}),
            ("aws_s3_bucket_public_access_block", "b", {**BLOCK_ALL, "restrict_public_buckets": False}),
            refs={"aws_s3_bucket_public_access_block.b": LINK},
        )
        self.assertEqual(hits(plan, "PG002"), ["aws_s3_bucket_public_access_block.b"])

    def test_full_access_block_passes(self):
        plan = make_plan(
            ("aws_s3_bucket", "b", {}),
            ("aws_s3_bucket_public_access_block", "b", BLOCK_ALL),
            refs={"aws_s3_bucket_public_access_block.b": LINK},
        )
        self.assertEqual(hits(plan, "PG002"), [])

    def test_account_wide_block_covers_all_buckets(self):
        plan = make_plan(("aws_s3_bucket", "b", {}), ("aws_s3_account_public_access_block", "acct", BLOCK_ALL))
        self.assertEqual(hits(plan, "PG002"), [])

    def test_versioning(self):
        self.assertEqual(hits(make_plan(("aws_s3_bucket", "b", {})), "PG003"), ["aws_s3_bucket.b"])
        on = make_plan(
            ("aws_s3_bucket", "b", {}),
            ("aws_s3_bucket_versioning", "b", {"versioning_configuration": [{"status": "Enabled"}]}),
            refs={"aws_s3_bucket_versioning.b": LINK},
        )
        self.assertEqual(hits(on, "PG003"), [])

    def test_old_inline_versioning(self):
        plan = make_plan(("aws_s3_bucket", "b", {"versioning": [{"enabled": True}]}))
        self.assertEqual(hits(plan, "PG003"), [])


class SecurityGroupTest(unittest.TestCase):
    def test_ssh_open_to_internet(self):
        self.assertEqual(hits(sg(ingress(22, 22)), "PG004"), ["aws_security_group.sg"])

    def test_rdp_inside_a_range(self):
        self.assertEqual(hits(sg(ingress(3000, 4000)), "PG004"), ["aws_security_group.sg"])

    def test_ssh_from_private_range_is_fine(self):
        self.assertEqual(hits(sg(ingress(22, 22, cidr="10.0.0.0/8")), "PG004"), [])

    def test_https_is_fine(self):
        self.assertEqual(hits(sg(ingress(443, 443)), "PG004"), [])
        self.assertEqual(hits(sg(ingress(443, 443)), "PG005"), [])

    def test_ipv6_internet(self):
        rule = {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}
        self.assertEqual(hits(sg(rule), "PG004"), ["aws_security_group.sg"])

    def test_all_traffic_is_pg005_not_pg004(self):
        plan = sg(ingress(0, 0, protocol="-1"))
        self.assertEqual(hits(plan, "PG005"), ["aws_security_group.sg"])
        self.assertEqual(hits(plan, "PG004"), [])

    def test_standalone_rule_resources(self):
        plan = make_plan(
            ("aws_security_group_rule", "r", {"type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}),
            ("aws_vpc_security_group_ingress_rule", "v", {"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"}),
        )
        self.assertEqual(hits(plan, "PG004"), ["aws_security_group_rule.r"])
        self.assertEqual(hits(plan, "PG005"), ["aws_vpc_security_group_ingress_rule.v"])

    def test_egress_rules_are_ignored(self):
        plan = make_plan(("aws_security_group_rule", "r", {"type": "egress", "protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}))
        self.assertEqual(hits(plan, "PG005"), [])


class DatabaseAndComputeTest(unittest.TestCase):
    def test_rds(self):
        bad = make_plan(("aws_db_instance", "db", {"publicly_accessible": True, "storage_encrypted": False, "backup_retention_period": 0}))
        good = make_plan(("aws_db_instance", "db", {"publicly_accessible": False, "storage_encrypted": True, "backup_retention_period": 7}))
        for rule in ("PG006", "PG007", "PG011"):
            self.assertEqual(hits(bad, rule), ["aws_db_instance.db"], rule)
            self.assertEqual(hits(good, rule), [], rule)

    def test_unknown_values_are_not_flagged(self):
        # Values Terraform only knows after apply are missing from the plan.
        self.assertEqual(hits(make_plan(("aws_db_instance", "db", {})), "PG007"), [])

    def test_ebs(self):
        self.assertEqual(hits(make_plan(("aws_ebs_volume", "v", {"encrypted": False})), "PG008"), ["aws_ebs_volume.v"])
        self.assertEqual(hits(make_plan(("aws_ebs_volume", "v", {"encrypted": True})), "PG008"), [])

    def test_imdsv2(self):
        bad = make_plan(("aws_instance", "i", {"metadata_options": [{"http_tokens": "optional"}]}))
        none = make_plan(("aws_instance", "i", {"metadata_options": []}))
        good = make_plan(("aws_instance", "i", {"metadata_options": [{"http_tokens": "required"}]}))
        self.assertEqual(hits(bad, "PG012"), ["aws_instance.i"])
        self.assertEqual(hits(none, "PG012"), ["aws_instance.i"])
        self.assertEqual(hits(good, "PG012"), [])

    def test_cloudtrail(self):
        bad = make_plan(("aws_cloudtrail", "t", {"is_multi_region_trail": False, "enable_log_file_validation": True}))
        good = make_plan(("aws_cloudtrail", "t", {"is_multi_region_trail": True, "enable_log_file_validation": True}))
        self.assertEqual(hits(bad, "PG010"), ["aws_cloudtrail.t"])
        self.assertEqual(hits(good, "PG010"), [])


class IamTest(unittest.TestCase):
    def policy(self, statement):
        return make_plan(("aws_iam_policy", "p", {"policy": json.dumps({"Statement": statement})}))

    def test_admin_policy(self):
        self.assertEqual(hits(self.policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}]), "PG009"), ["aws_iam_policy.p"])

    def test_star_inside_a_list(self):
        st = {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}
        self.assertEqual(hits(self.policy([st]), "PG009"), ["aws_iam_policy.p"])

    def test_single_statement_object(self):
        self.assertEqual(hits(self.policy({"Effect": "Allow", "Action": "*", "Resource": "*"}), "PG009"), ["aws_iam_policy.p"])

    def test_deny_star_is_fine(self):
        self.assertEqual(hits(self.policy([{"Effect": "Deny", "Action": "*", "Resource": "*"}]), "PG009"), [])

    def test_scoped_policy_is_fine(self):
        st = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
        self.assertEqual(hits(self.policy([st]), "PG009"), [])

    def test_unknown_policy_is_skipped(self):
        self.assertEqual(hits(make_plan(("aws_iam_policy", "p", {})), "PG009"), [])


if __name__ == "__main__":
    unittest.main()
