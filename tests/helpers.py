"""Small helpers to build fake plans for tests."""

from planguard.plan import Plan, parse_plan
from planguard.scan import scan


def make_plan(*resources, refs=None) -> Plan:
    """resources: (type, name, values) tuples. refs: {"type.name": {"attr": ["target"]}}"""
    refs = refs or {}
    planned, config = [], []
    for type_, name, values in resources:
        addr = f"{type_}.{name}"
        planned.append({"address": addr, "mode": "managed", "type": type_, "name": name, "values": values})
        exprs = {attr: {"references": r} for attr, r in refs.get(addr, {}).items()}
        config.append({"address": addr, "mode": "managed", "type": type_, "name": name, "expressions": exprs})
    return parse_plan(
        {"planned_values": {"root_module": {"resources": planned}}, "configuration": {"root_module": {"resources": config}}}
    )


def hits(plan: Plan, rule_id: str) -> list[str]:
    """Addresses flagged by one rule."""
    return [f.resource for f in scan(plan).findings if f.rule.id == rule_id]
