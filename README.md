# planguard

[![ci](https://github.com/PrimelPJ/planguard/actions/workflows/ci.yml/badge.svg)](https://github.com/PrimelPJ/planguard/actions/workflows/ci.yml)

planguard checks a Terraform plan for security problems **before** you run `terraform apply`.

It looks for things like open SSH ports, public storage buckets, databases on the internet, and admin IAM policies. It works for **AWS** and **Azure**, and it maps every check to **NIST SP 800-53** controls so you also get a simple compliance report.

No dependencies. Just Python 3.11+.

## Why scan the plan instead of the `.tf` files?

`.tf` files are full of variables, modules and loops. The plan is what Terraform will *actually* build, with all of that already worked out. So planguard sees the real values, not guesses.

## Quick start

```bash
pip install git+https://github.com/PrimelPJ/planguard

terraform plan -out tfplan
terraform show -json tfplan > plan.json

planguard scan plan.json
```

Try it on the sample plan in this repo:

```bash
planguard scan examples/insecure-plan.json
```

```
Scanned 17 resources with 19 rules. Found 22 problems (3 critical, 10 high, 9 medium).

CRITICAL  PG004  aws_security_group.web
                 SSH or RDP is open to the whole internet: SSH (port 22) is open to 0.0.0.0/0
                 Fix: Only allow your own IP range, or close the port and use AWS Systems Manager Session Manager.

CRITICAL  PG009  aws_iam_policy.ci
                 IAM policy gives full admin access: allows Action "*" on Resource "*"
                 Fix: List only the actions and resources the role really needs.
...
```

## What it checks

| ID | Cloud | Severity | Check |
|---|---|---|---|
| PG001 | AWS | high | S3 bucket has a public ACL |
| PG002 | AWS | high | S3 bucket is not protected by a public access block |
| PG003 | AWS | medium | S3 bucket does not keep old versions |
| PG004 | AWS | critical | SSH or RDP is open to the whole internet |
| PG005 | AWS | high | Every port is open to the whole internet |
| PG006 | AWS | high | Database can be reached from the internet |
| PG007 | AWS | high | Database storage is not encrypted |
| PG008 | AWS | medium | Disk is not encrypted |
| PG009 | AWS | critical | IAM policy gives full admin access |
| PG010 | AWS | medium | CloudTrail is missing key settings |
| PG011 | AWS | medium | Database backups are turned off |
| PG012 | AWS | medium | Server does not require IMDSv2 |
| PG101 | Azure | high | Storage account allows plain HTTP |
| PG102 | Azure | medium | Storage account allows old TLS versions |
| PG103 | Azure | high | Storage allows public access to files |
| PG104 | Azure | critical | SSH or RDP is open to the whole internet |
| PG105 | Azure | medium | Key Vault can be deleted for good right away |
| PG106 | Azure | high | SQL server can be reached from the internet |
| PG107 | Azure | medium | Linux VM allows password login |

Each rule explains why it matters and how to fix it. See [docs/rules.md](docs/rules.md).

## Output formats

```bash
planguard scan plan.json                    # readable text (default)
planguard scan plan.json -f json            # for scripts
planguard scan plan.json -f sarif -o out.sarif   # for GitHub code scanning
planguard scan plan.json -f markdown -o report.md  # compliance report
```

The Markdown report lists every problem, every accepted risk, and a pass/fail table for each NIST control:

| Control | Name | Rules | Status |
|---|---|---|---|
| AC-6 | Least Privilege | PG009 | Fail |
| SC-8 | Transmission Confidentiality and Integrity | PG101, PG102 | Pass |
| SC-28 | Protection of Information at Rest | PG007, PG008 | Pass (with waiver) |

## Accepting a risk (waivers)

Sometimes a problem is fine for now. Instead of turning the rule off for everyone, add a **waiver** in `planguard.toml`:

```toml
[[waiver]]
rule = "PG003"
resource = "aws_s3_bucket.site"
reason = "Site files are rebuilt from git on every deploy, so old versions are not needed."
owner = "primel"
expires = 2027-06-30
```

Rules for waivers:

- Every waiver **must** have a reason and an end date. No silent, forever exceptions.
- When the end date passes, the waiver stops working and the problem comes back.
- Waivers that match nothing are pointed out so you can clean them up.
- `rule` and `resource` accept wildcards, like `PG00*` or `module.dev.*`.

planguard reads `planguard.toml` from the current folder, or from `--config`.

## Use it in GitHub Actions

```yaml
- run: terraform plan -out tfplan && terraform show -json tfplan > plan.json

- uses: PrimelPJ/planguard@main
  with:
    plan: plan.json
    fail-on: high        # block the merge on high or critical problems
```

To show problems in the GitHub Security tab, write SARIF and upload it:

```yaml
- uses: PrimelPJ/planguard@main
  with:
    plan: plan.json
    format: sarif
    output: planguard.sarif
    fail-on: none
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: planguard.sarif
```

## Options

```
planguard scan PLAN [-f text|json|sarif|markdown] [-o FILE] [-c CONFIG]
                    [--fail-on low|medium|high|critical|none]
                    [--min-severity low|medium|high|critical]
                    [--cloud aws|azure]
planguard rules [--cloud aws|azure]
```

Exit codes: `0` nothing at or above `--fail-on`, `1` problems found, `2` bad input.

## How it works

1. **Read the plan.** planguard walks every module in `planned_values` and keeps each resource's final values.
2. **Connect resources.** Some problems need two resources. For example, a bucket and its separate public access block. The bucket name is often unknown until apply, so planguard follows the references in the plan's `configuration` section to link them.
3. **Run the rules.** Each rule is a small Python function. If a value is unknown until apply, the rule skips it instead of guessing.
4. **Apply waivers** and write the report.

Adding a rule is about ten lines:

```python
@rule("PG013", "Load balancer allows plain HTTP", "medium", "aws", ["SC-8"],
      risk="Traffic is not encrypted.", fix="Use an HTTPS listener.")
def lb_http(plan):
    for lb in plan.of_type("aws_lb_listener"):
        if lb.get("protocol") == "HTTP":
            yield lb, "listener uses HTTP"
```

## Limits

- It only sees what is in the plan. Resources made outside Terraform are not checked.
- The NIST mapping shows which controls a rule *helps with*. A "Pass" means planguard found nothing wrong, not that the whole control is met.
- The example plans in `examples/` are small hand-made plans for testing and demos.

## Development

```bash
pip install -e .
python -m unittest discover -s tests -t .
python scripts/rules_doc.py     # rebuild docs/rules.md after changing a rule
```

## License

MIT
