"""Read a Terraform plan (the output of `terraform show -json`) into simple objects."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


class PlanError(Exception):
    """The file is not a Terraform plan we can read."""


_INDEX = re.compile(r"\[[^\]]*\]")


def _strip_index(address: str) -> str:
    """module.net[0] -> module.net"""
    return _INDEX.sub("", address)


@dataclass
class Resource:
    """One resource from the plan, with the values Terraform will set."""

    address: str  # full address, like module.net.aws_security_group.web[0]
    module: str  # module path, "" for the root module
    type: str  # like aws_s3_bucket
    name: str  # like logs
    values: dict[str, Any]
    refs: dict[str, list[str]] = field(default_factory=dict)  # attribute -> what it points at

    @property
    def local_name(self) -> str:
        return f"{self.type}.{self.name}"

    def get(self, key: str, default: Any = None) -> Any:
        value = self.values.get(key)
        return default if value is None else value

    def known(self, key: str) -> bool:
        """Terraform leaves out values it will only know after apply."""
        return key in self.values

    def block(self, key: str) -> dict[str, Any]:
        """Return the first nested block (Terraform stores blocks as lists), or {}."""
        value = self.values.get(key)
        if isinstance(value, list) and value and isinstance(value[0], dict):
            return value[0]
        return {}

    def points_to(self, attr: str, target: "Resource") -> bool:
        """True if this resource's `attr` points at `target`.

        First we look at the references in the config (works even when the
        target's name is not known yet). Then we compare plain values.
        """
        if _strip_index(self.module) != _strip_index(target.module):
            return False
        for ref in self.refs.get(attr, []):
            if ref == target.local_name or ref.startswith((target.local_name + ".", target.local_name + "[")):
                return True
        value = self.values.get(attr)
        if not isinstance(value, str) or not value:
            return False
        return value in (target.values.get("id"), target.values.get("bucket"), target.values.get("name"))


@dataclass
class Plan:
    resources: list[Resource]
    source: str = "plan.json"

    def of_type(self, *types: str) -> list[Resource]:
        return [r for r in self.resources if r.type in types]


def load_plan(path: str | Path) -> Plan:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PlanError(f"file not found: {path}") from None
    except json.JSONDecodeError as err:
        raise PlanError(f"{path} is not valid JSON ({err.msg}, line {err.lineno})") from None
    return parse_plan(data, source=str(path))


def parse_plan(data: Any, source: str = "plan.json") -> Plan:
    if not isinstance(data, dict) or "planned_values" not in data:
        raise PlanError(
            "this does not look like a Terraform plan. "
            "Make one with: terraform plan -out tfplan && terraform show -json tfplan > plan.json"
        )

    refs: dict[tuple[str, str], dict[str, list[str]]] = {}
    _collect_refs(data.get("configuration", {}).get("root_module", {}), "", refs)

    resources = []
    for module, raw in _walk(data["planned_values"].get("root_module", {})):
        if raw.get("mode", "managed") != "managed":
            continue  # skip data sources
        local = f"{raw['type']}.{raw['name']}"
        resources.append(
            Resource(
                address=raw.get("address", local),
                module=module,
                type=raw["type"],
                name=raw["name"],
                values=raw.get("values") or {},
                refs=refs.get((_strip_index(module), local), {}),
            )
        )
    return Plan(resources=resources, source=source)


def _walk(module: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    address = module.get("address", "")
    for raw in module.get("resources", []):
        yield address, raw
    for child in module.get("child_modules", []):
        yield from _walk(child)


def _collect_refs(module: dict[str, Any], prefix: str, out: dict) -> None:
    for raw in module.get("resources", []):
        attrs = {}
        for attr, expr in (raw.get("expressions") or {}).items():
            if isinstance(expr, dict) and expr.get("references"):
                attrs[attr] = list(expr["references"])
        out[(prefix, raw["address"])] = attrs
    for name, call in (module.get("module_calls") or {}).items():
        child_prefix = f"{prefix}.module.{name}" if prefix else f"module.{name}"
        _collect_refs(call.get("module", {}), child_prefix, out)
