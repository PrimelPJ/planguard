"""Checks for AWS resources."""

from __future__ import annotations

import json
from typing import Iterator

from ..plan import Plan, Resource
from .base import Hit, admin_ports_in, is_internet, rule

# ---------- S3 ----------

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
BLOCK_SETTINGS = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]


@rule(
    "PG001",
    "S3 bucket has a public ACL",
    "high",
    "aws",
    ["AC-3", "SC-7"],
    risk="Anyone on the internet (or any AWS user) can read the files in this bucket.",
    fix="Set the ACL to private and share files with signed URLs or a bucket policy that names who can read.",
)
def s3_public_acl(plan: Plan) -> Iterator[Hit]:
    for res in plan.of_type("aws_s3_bucket", "aws_s3_bucket_acl"):
        acl = res.get("acl")
        if acl in PUBLIC_ACLS:
            yield res, f"ACL is '{acl}', which opens the bucket to the public"


@rule(
    "PG002",
    "S3 bucket is not protected by a public access block",
    "high",
    "aws",
    ["AC-3", "SC-7"],
    risk="Without a public access block, one wrong ACL or policy can make the bucket public.",
    fix="Add an aws_s3_bucket_public_access_block for the bucket with all four settings set to true.",
)
def s3_public_access_block(plan: Plan) -> Iterator[Hit]:
    # An account-wide block with every setting on protects all buckets.
    for account in plan.of_type("aws_s3_account_public_access_block"):
        if all(account.get(s) is True for s in BLOCK_SETTINGS):
            return

    blocks = plan.of_type("aws_s3_bucket_public_access_block")
    for bucket in plan.of_type("aws_s3_bucket"):
        mine = [b for b in blocks if b.points_to("bucket", bucket)]
        if not mine:
            yield bucket, "no public access block is attached to this bucket"
            continue
        off = [s for s in BLOCK_SETTINGS if mine[0].known(s) and mine[0].get(s) is not True]
        if off:
            yield mine[0], f"public access block has these turned off: {', '.join(off)}"


@rule(
    "PG003",
    "S3 bucket does not keep old versions",
    "medium",
    "aws",
    ["CP-9"],
    risk="If a file is deleted or overwritten (by mistake or by ransomware), it cannot be brought back.",
    fix="Add aws_s3_bucket_versioning for the bucket with status = \"Enabled\".",
)
def s3_versioning(plan: Plan) -> Iterator[Hit]:
    versioning = plan.of_type("aws_s3_bucket_versioning")
    for bucket in plan.of_type("aws_s3_bucket"):
        if bucket.block("versioning").get("enabled") is True:
            continue  # old inline style
        mine = [v for v in versioning if v.points_to("bucket", bucket)]
        if not mine:
            yield bucket, "versioning is not set up for this bucket"
            continue
        status = mine[0].block("versioning_configuration").get("status")
        if status != "Enabled":
            yield mine[0], f"versioning status is '{status}', not 'Enabled'"


# ---------- Security groups ----------


def _ingress(plan: Plan) -> Iterator[tuple[Resource, str, int, int, list[str]]]:
    """Every inbound rule as (resource, protocol, from_port, to_port, sources)."""
    for sg in plan.of_type("aws_security_group"):
        for r in sg.get("ingress", []):
            sources = list(r.get("cidr_blocks") or []) + list(r.get("ipv6_cidr_blocks") or [])
            yield sg, str(r.get("protocol")), int(r.get("from_port") or 0), int(r.get("to_port") or 0), sources
    for r in plan.of_type("aws_security_group_rule"):
        if r.get("type") == "ingress":
            sources = list(r.get("cidr_blocks", [])) + list(r.get("ipv6_cidr_blocks", []))
            yield r, str(r.get("protocol")), int(r.get("from_port") or 0), int(r.get("to_port") or 0), sources
    for r in plan.of_type("aws_vpc_security_group_ingress_rule"):
        sources = [c for c in (r.get("cidr_ipv4"), r.get("cidr_ipv6")) if c]
        yield r, str(r.get("ip_protocol")), int(r.get("from_port") or 0), int(r.get("to_port") or 0), sources


def _all_traffic(protocol: str, low: int, high: int) -> bool:
    return protocol.lower() in ("-1", "all") or (low <= 0 and high >= 65535)


@rule(
    "PG004",
    "SSH or RDP is open to the whole internet",
    "critical",
    "aws",
    ["SC-7", "AC-17"],
    risk="Bots scan the internet for open SSH and RDP all day and try to guess passwords or use known bugs.",
    fix="Only allow your own IP range, or close the port and use AWS Systems Manager Session Manager.",
)
def sg_admin_ports(plan: Plan) -> Iterator[Hit]:
    for res, protocol, low, high, sources in _ingress(plan):
        if _all_traffic(protocol, low, high) or protocol.lower() not in ("tcp", "6"):
            continue  # all-traffic rules are reported by PG005
        open_to = [s for s in sources if is_internet(s)]
        ports = admin_ports_in(low, high)
        if open_to and ports:
            yield res, f"{' and '.join(ports)} is open to {', '.join(open_to)}"


@rule(
    "PG005",
    "Every port is open to the whole internet",
    "high",
    "aws",
    ["SC-7"],
    risk="Every service on the server can be reached by anyone, including ones you forgot were running.",
    fix="Only open the ports you need (like 443), and only to the sources that need them.",
)
def sg_all_ports(plan: Plan) -> Iterator[Hit]:
    for res, protocol, low, high, sources in _ingress(plan):
        open_to = [s for s in sources if is_internet(s)]
        if open_to and _all_traffic(protocol, low, high):
            yield res, f"all inbound traffic is allowed from {', '.join(open_to)}"


# ---------- Databases ----------


@rule(
    "PG006",
    "Database can be reached from the internet",
    "high",
    "aws",
    ["SC-7", "AC-3"],
    risk="The database gets a public address, so attackers can try to log in to it directly.",
    fix="Set publicly_accessible = false and reach the database from inside the VPC.",
)
def rds_public(plan: Plan) -> Iterator[Hit]:
    for db in plan.of_type("aws_db_instance"):
        if db.get("publicly_accessible") is True:
            yield db, "publicly_accessible is true"


@rule(
    "PG007",
    "Database storage is not encrypted",
    "high",
    "aws",
    ["SC-28"],
    risk="Anyone who gets a copy of the disk or a snapshot can read the data.",
    fix="Set storage_encrypted = true (this can only be set when the database is created).",
)
def rds_encryption(plan: Plan) -> Iterator[Hit]:
    for db in plan.of_type("aws_db_instance", "aws_rds_cluster"):
        if db.known("storage_encrypted") and db.get("storage_encrypted") is not True:
            yield db, "storage_encrypted is not true"


@rule(
    "PG008",
    "Disk is not encrypted",
    "medium",
    "aws",
    ["SC-28"],
    risk="Anyone who gets a copy of the disk or a snapshot can read the data on it.",
    fix="Set encrypted = true on the volume, or turn on EBS encryption by default for the account.",
)
def ebs_encryption(plan: Plan) -> Iterator[Hit]:
    for vol in plan.of_type("aws_ebs_volume"):
        if vol.known("encrypted") and vol.get("encrypted") is not True:
            yield vol, "volume is not encrypted"
    for vm in plan.of_type("aws_instance"):
        root = vm.block("root_block_device")
        if "encrypted" in root and root["encrypted"] is not True:
            yield vm, "root disk is not encrypted"


@rule(
    "PG009",
    "IAM policy gives full admin access",
    "critical",
    "aws",
    ["AC-6"],
    risk="Whoever gets this policy can do anything in the account, including deleting everything.",
    fix="List only the actions and resources the role really needs.",
)
def iam_admin(plan: Plan) -> Iterator[Hit]:
    types = ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy")
    for pol in plan.of_type(*types):
        try:
            doc = json.loads(pol.get("policy", ""))
        except (TypeError, ValueError):
            continue  # not known yet, or not JSON
        statements = doc.get("Statement", []) if isinstance(doc, dict) else []
        if isinstance(statements, dict):
            statements = [statements]
        for st in statements:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            if _has_star(st.get("Action")) and _has_star(st.get("Resource")):
                yield pol, 'allows Action "*" on Resource "*"'
                break


def _has_star(value: object) -> bool:
    if isinstance(value, str):
        return value == "*"
    return isinstance(value, list) and "*" in value


@rule(
    "PG010",
    "CloudTrail is missing key settings",
    "medium",
    "aws",
    ["AU-2", "AU-9", "AU-12"],
    risk="Activity in some regions is not logged, or someone could edit the logs without you knowing.",
    fix="Set is_multi_region_trail = true and enable_log_file_validation = true.",
)
def cloudtrail(plan: Plan) -> Iterator[Hit]:
    for trail in plan.of_type("aws_cloudtrail"):
        missing = []
        if trail.known("is_multi_region_trail") and trail.get("is_multi_region_trail") is not True:
            missing.append("it only logs one region")
        if trail.known("enable_log_file_validation") and trail.get("enable_log_file_validation") is not True:
            missing.append("log file validation is off")
        if missing:
            yield trail, "; ".join(missing)


@rule(
    "PG011",
    "Database backups are turned off",
    "medium",
    "aws",
    ["CP-9"],
    risk="If data is lost or corrupted, there is no backup to restore from.",
    fix="Set backup_retention_period to at least 7 days.",
)
def rds_backups(plan: Plan) -> Iterator[Hit]:
    for db in plan.of_type("aws_db_instance"):
        if db.known("backup_retention_period") and db.get("backup_retention_period") == 0:
            yield db, "backup_retention_period is 0"


@rule(
    "PG012",
    "Server does not require IMDSv2",
    "medium",
    "aws",
    ["AC-3", "CM-6"],
    risk="A bug in an app on the server can be used to steal the server's AWS keys (this is how the 2019 Capital One breach worked).",
    fix='Add a metadata_options block with http_tokens = "required".',
)
def imdsv2(plan: Plan) -> Iterator[Hit]:
    for res in plan.of_type("aws_instance", "aws_launch_template"):
        if not res.known("metadata_options"):
            continue
        tokens = res.block("metadata_options").get("http_tokens")
        if tokens != "required":
            yield res, f"http_tokens is '{tokens or 'not set'}', so the old IMDSv1 still works"
