"""Write docs/rules.md from the rule list, so the docs never drift from the code.

Run: python scripts/rules_doc.py
Check only: python scripts/rules_doc.py --check
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from planguard.report import CONTROL_NAMES  # noqa: E402
from planguard.rules import RULES  # noqa: E402

TARGET = Path(__file__).resolve().parent.parent / "docs" / "rules.md"


def render() -> str:
    out = ["# Rules", "", "This file is made by `scripts/rules_doc.py`. Do not edit it by hand.", ""]
    out += ["| ID | Cloud | Severity | Check |", "|---|---|---|---|"]
    out += [f"| [{r.id}](#{r.id.lower()}) | {r.cloud} | {r.severity} | {r.title} |" for r in RULES]
    for r in RULES:
        controls = ", ".join(f"{c} ({CONTROL_NAMES.get(c, '')})" for c in r.controls)
        out += [
            "",
            f"## {r.id}",
            "",
            f"**{r.title}** ({r.cloud}, {r.severity})",
            "",
            f"- **Why it matters:** {r.risk}",
            f"- **How to fix:** {r.fix}",
            f"- **NIST SP 800-53:** {controls}",
        ]
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    text = render()
    if "--check" in sys.argv:
        if not TARGET.exists() or TARGET.read_text() != text:
            print("docs/rules.md is out of date. Run: python scripts/rules_doc.py")
            sys.exit(1)
        print("docs/rules.md is up to date")
    else:
        TARGET.write_text(text)
        print(f"wrote {TARGET}")
