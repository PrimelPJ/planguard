"""Command line: planguard scan plan.json"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .plan import PlanError, load_plan
from .report import FORMATS, summary_line
from .rules import RULES, SEVERITIES
from .scan import Config, ConfigError, load_config, scan

DEFAULT_CONFIG = "planguard.toml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="planguard",
        description="Find security problems in a Terraform plan before you apply it.",
    )
    parser.add_argument("--version", action="version", version=f"planguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a plan file")
    s.add_argument("plan", help="plan as JSON (terraform show -json tfplan > plan.json)")
    s.add_argument("-f", "--format", choices=FORMATS, default="text", help="output format (default: text)")
    s.add_argument("-o", "--output", help="write the report to this file instead of the screen")
    s.add_argument("-c", "--config", help=f"config file with waivers (default: {DEFAULT_CONFIG} if it exists)")
    s.add_argument(
        "--fail-on",
        choices=[*SEVERITIES, "none"],
        default="high",
        help="exit with code 1 if a problem this bad or worse is found (default: high)",
    )
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide problems below this level")
    s.add_argument("--cloud", choices=["aws", "azure"], action="append", help="only run rules for this cloud")

    r = sub.add_parser("rules", help="list every rule")
    r.add_argument("--cloud", choices=["aws", "azure"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        return list_rules(args.cloud)

    try:
        plan = load_plan(args.plan)
        if args.config:
            config = load_config(args.config)
        elif Path(DEFAULT_CONFIG).exists():
            config = load_config(DEFAULT_CONFIG)
        else:
            config = Config()
    except (PlanError, ConfigError) as err:
        print(f"planguard: {err}", file=sys.stderr)
        return 2

    result = scan(plan, config, min_severity=args.min_severity, clouds=set(args.cloud or []))
    report = FORMATS[args.format](result)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(summary_line(result))
        print(f"Report written to {args.output}")
    else:
        sys.stdout.write(report)

    if args.fail_on == "none":
        return 0
    floor = SEVERITIES.index(args.fail_on)
    return 1 if any(f.rule.rank >= floor for f in result.active) else 0


def list_rules(cloud: str | None) -> int:
    for r in RULES:
        if cloud and r.cloud != cloud:
            continue
        print(f"{r.id}  {r.severity:<8}  {r.cloud:<5}  {r.title}")
    return 0
