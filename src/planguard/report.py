"""Turn scan results into text, JSON, SARIF or a Markdown report."""

from __future__ import annotations

import json
from datetime import date

from . import __version__
from .rules import SEVERITIES
from .scan import Result, Waiver

# NIST SP 800-53 Rev. 5 control names, for the Markdown report.
CONTROL_NAMES = {
    "AC-3": "Access Enforcement",
    "AC-6": "Least Privilege",
    "AC-17": "Remote Access",
    "AU-2": "Event Logging",
    "AU-9": "Protection of Audit Information",
    "AU-12": "Audit Record Generation",
    "CM-6": "Configuration Settings",
    "CP-9": "System Backup",
    "IA-2": "Identification and Authentication",
    "IA-5": "Authenticator Management",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Management",
    "SC-13": "Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
}

HELP_URL = "https://github.com/PrimelPJ/planguard/blob/main/docs/rules.md"


def summary_line(result: Result) -> str:
    total = len(result.active)
    parts = [f"{result.count(s)} {s}" for s in reversed(SEVERITIES) if result.count(s)]
    line = f"Scanned {len(result.plan.resources)} resources with {len(result.rules)} rules. "
    if total == 0:
        line += "No problems found."
    else:
        line += f"Found {total} problem{'s' if total != 1 else ''} ({', '.join(parts)})."
    if result.waived:
        line += f" {len(result.waived)} waived."
    return line


def _waiver_text(w: Waiver) -> str:
    who = f", owner {w.owner}" if w.owner else ""
    return f"{w.rule} on {w.resource} (ended {w.expires}{who})"


def to_text(result: Result) -> str:
    out = [summary_line(result), ""]
    for f in result.active:
        out.append(f"{f.rule.severity.upper():<9} {f.rule.id}  {f.resource}")
        out.append(f"{'':<17}{f.rule.title}: {f.message}")
        out.append(f"{'':<17}Fix: {f.rule.fix}")
        out.append("")
    if result.waived:
        out.append("Waived (accepted risks):")
        for f in result.waived:
            out.append(f"  {f.rule.id}  {f.resource}  until {f.waiver.expires}: {f.waiver.reason}")
        out.append("")
    for w in result.expired_waivers:
        out.append(f"Warning: waiver has ended and no longer applies: {_waiver_text(w)}")
    for w in result.unused_waivers:
        out.append(f"Note: waiver matched nothing and can be removed: {w.rule} on {w.resource}")
    return "\n".join(out).rstrip() + "\n"


def _finding_dict(f) -> dict:
    d = {
        "rule": f.rule.id,
        "title": f.rule.title,
        "severity": f.rule.severity,
        "cloud": f.rule.cloud,
        "resource": f.resource,
        "message": f.message,
        "risk": f.rule.risk,
        "fix": f.rule.fix,
        "controls": list(f.rule.controls),
    }
    if f.waiver:
        d["waiver"] = {"reason": f.waiver.reason, "owner": f.waiver.owner, "expires": f.waiver.expires.isoformat()}
    return d


def _waiver_dict(w: Waiver) -> dict:
    return {"rule": w.rule, "resource": w.resource, "reason": w.reason, "owner": w.owner, "expires": w.expires.isoformat()}


def to_json(result: Result) -> str:
    data = {
        "tool": "planguard",
        "version": __version__,
        "plan": result.plan.source,
        "summary": {
            "resources": len(result.plan.resources),
            "rules": len(result.rules),
            "problems": len(result.active),
            "waived": len(result.waived),
            **{s: result.count(s) for s in SEVERITIES},
        },
        "findings": [_finding_dict(f) for f in result.active],
        "waived": [_finding_dict(f) for f in result.waived],
        "expired_waivers": [_waiver_dict(w) for w in result.expired_waivers],
        "unused_waivers": [_waiver_dict(w) for w in result.unused_waivers],
    }
    return json.dumps(data, indent=2) + "\n"


# GitHub uses "security-severity" to label code scanning alerts.
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def to_sarif(result: Result) -> str:
    rules = []
    index = {}
    for i, r in enumerate(result.rules):
        index[r.id] = i
        rules.append(
            {
                "id": r.id,
                "name": r.title,
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.risk},
                "help": {"text": f"{r.risk}\nFix: {r.fix}", "markdown": f"{r.risk}\n\n**Fix:** {r.fix}"},
                "helpUri": f"{HELP_URL}#{r.id.lower()}",
                "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
                "properties": {
                    "security-severity": SARIF_SCORE[r.severity],
                    "tags": ["security", r.cloud, *[f"NIST-800-53:{c}" for c in r.controls]],
                },
            }
        )

    results = []
    for f in result.findings:
        item = {
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": SARIF_LEVEL[f.rule.severity],
            "message": {"text": f"{f.resource}: {f.message}"},
            "locations": [
                {
                    "physicalLocation": {"artifactLocation": {"uri": result.plan.source}, "region": {"startLine": 1}},
                    "logicalLocations": [{"name": f.resource, "kind": "resource"}],
                }
            ],
            "partialFingerprints": {"planguard/v1": f"{f.rule.id}:{f.resource}"},
        }
        if f.waiver:
            item["suppressions"] = [{"kind": "external", "justification": f.waiver.reason}]
        results.append(item)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "planguard",
                        "version": __version__,
                        "informationUri": "https://github.com/PrimelPJ/planguard",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(result: Result, today: date | None = None) -> str:
    today = today or date.today()
    out = [
        "# planguard report",
        "",
        f"- **Plan:** `{result.plan.source}`",
        f"- **Date:** {today.isoformat()}",
        f"- **Result:** {summary_line(result)}",
        "",
        "## Problems",
        "",
    ]
    if result.active:
        out += ["| Severity | Rule | Resource | Problem | Fix |", "|---|---|---|---|---|"]
        for f in result.active:
            out.append(
                f"| {f.rule.severity} | {f.rule.id} | `{_cell(f.resource)}` | {_cell(f.message)} | {_cell(f.rule.fix)} |"
            )
    else:
        out.append("No problems found.")

    out += ["", "## Accepted risks (waivers)", ""]
    if result.waived:
        out += ["| Rule | Resource | Reason | Owner | Ends |", "|---|---|---|---|---|"]
        for f in result.waived:
            w = f.waiver
            out.append(f"| {f.rule.id} | `{_cell(f.resource)}` | {_cell(w.reason)} | {_cell(w.owner or '-')} | {w.expires} |")
    else:
        out.append("None.")
    if result.expired_waivers:
        out += ["", "**Ended waivers** (no longer applied, the problems above are open again):", ""]
        out += [f"- {_waiver_text(w)}" for w in result.expired_waivers]

    out += [
        "",
        "## NIST SP 800-53 controls",
        "",
        "Each rule is mapped to the controls it helps with. A control **fails** if any open problem touches it.",
        "",
        "| Control | Name | Rules | Status |",
        "|---|---|---|---|",
    ]
    controls: dict[str, list[str]] = {}
    for r in result.rules:
        for c in r.controls:
            controls.setdefault(c, []).append(r.id)
    failing = {c for f in result.active for c in f.rule.controls}
    waived = {c for f in result.waived for c in f.rule.controls}
    for c in sorted(controls, key=_control_key):
        if c in failing:
            status = "Fail"
        elif c in waived:
            status = "Pass (with waiver)"
        else:
            status = "Pass"
        out.append(f"| {c} | {CONTROL_NAMES.get(c, '')} | {', '.join(controls[c])} | {status} |")

    out += ["", "_A pass here means planguard's checks found nothing. It does not prove the whole control is met._", ""]
    return "\n".join(out)


def _control_key(control: str) -> tuple[str, int]:
    family, _, number = control.partition("-")
    return family, int(number) if number.isdigit() else 0


FORMATS = {"text": to_text, "json": to_json, "sarif": to_sarif, "markdown": to_markdown}
