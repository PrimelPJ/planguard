"""Checks for Azure resources."""

from __future__ import annotations

from typing import Any, Iterator

from ..plan import Plan
from .base import Hit, admin_ports_in, is_internet, parse_ports, rule


@rule(
    "PG101",
    "Storage account allows plain HTTP",
    "high",
    "azure",
    ["SC-8"],
    risk="Data sent over HTTP is not encrypted, so anyone on the network path can read or change it.",
    fix="Set https_traffic_only_enabled = true (called enable_https_traffic_only in older providers).",
)
def storage_https(plan: Plan) -> Iterator[Hit]:
    for sa in plan.of_type("azurerm_storage_account"):
        for key in ("https_traffic_only_enabled", "enable_https_traffic_only"):
            if sa.known(key) and sa.values[key] is False:
                yield sa, f"{key} is false"
                break


@rule(
    "PG102",
    "Storage account allows old TLS versions",
    "medium",
    "azure",
    ["SC-8", "SC-13"],
    risk="TLS 1.0 and 1.1 have known weaknesses and are no longer seen as safe.",
    fix='Set min_tls_version = "TLS1_2".',
)
def storage_tls(plan: Plan) -> Iterator[Hit]:
    for sa in plan.of_type("azurerm_storage_account"):
        version = sa.get("min_tls_version")
        if version in ("TLS1_0", "TLS1_1"):
            yield sa, f"min_tls_version is {version}"


@rule(
    "PG103",
    "Storage allows public access to files",
    "high",
    "azure",
    ["AC-3", "SC-7"],
    risk="Files in public containers can be read by anyone who finds the URL, with no login.",
    fix='Set allow_nested_items_to_be_public = false and container_access_type = "private".',
)
def storage_public(plan: Plan) -> Iterator[Hit]:
    for sa in plan.of_type("azurerm_storage_account"):
        if sa.get("allow_nested_items_to_be_public") is True:
            yield sa, "allow_nested_items_to_be_public is true"
    for c in plan.of_type("azurerm_storage_container"):
        access = c.get("container_access_type")
        if access in ("blob", "container"):
            yield c, f"container_access_type is '{access}', so files can be read without logging in"


def _nsg_rules(plan: Plan) -> Iterator[tuple[Any, dict[str, Any]]]:
    """Every NSG rule as (resource, rule fields), from both standalone and inline rules."""
    for r in plan.of_type("azurerm_network_security_rule"):
        yield r, r.values
    for nsg in plan.of_type("azurerm_network_security_group"):
        for inline in nsg.get("security_rule", []):
            yield nsg, inline


def _list(fields: dict[str, Any], one: str, many: str) -> list[str]:
    values = list(fields.get(many) or [])
    if fields.get(one):
        values.append(fields[one])
    return values


@rule(
    "PG104",
    "SSH or RDP is open to the whole internet",
    "critical",
    "azure",
    ["SC-7", "AC-17"],
    risk="Bots scan the internet for open SSH and RDP all day and try to guess passwords or use known bugs.",
    fix="Only allow your own IP range, or close the port and use Azure Bastion.",
)
def nsg_admin_ports(plan: Plan) -> Iterator[Hit]:
    for res, f in _nsg_rules(plan):
        if str(f.get("direction", "")).lower() != "inbound" or str(f.get("access", "")).lower() != "allow":
            continue
        if str(f.get("protocol", "")).lower() not in ("tcp", "*"):
            continue
        sources = [s for s in _list(f, "source_address_prefix", "source_address_prefixes") if is_internet(s)]
        if not sources:
            continue
        found: list[str] = []
        for spec in _list(f, "destination_port_range", "destination_port_ranges"):
            ports = parse_ports(spec)
            if ports:
                found += [p for p in admin_ports_in(*ports) if p not in found]
        if found:
            label = f"rule '{f.get('name')}': " if f.get("name") else ""
            yield res, f"{label}{' and '.join(found)} is open to {', '.join(sources)}"


@rule(
    "PG105",
    "Key Vault can be deleted for good right away",
    "medium",
    "azure",
    ["CP-9", "SC-12"],
    risk="Someone (or a bad script) could delete the vault and its keys forever, with no way to get them back.",
    fix="Set purge_protection_enabled = true.",
)
def key_vault_purge(plan: Plan) -> Iterator[Hit]:
    for kv in plan.of_type("azurerm_key_vault"):
        if kv.known("purge_protection_enabled") and kv.get("purge_protection_enabled") is not True:
            yield kv, "purge_protection_enabled is false"


@rule(
    "PG106",
    "SQL server can be reached from the internet",
    "high",
    "azure",
    ["SC-7"],
    risk="Attackers can try to log in to the database server directly from anywhere.",
    fix="Set public_network_access_enabled = false and use a private endpoint.",
)
def sql_public(plan: Plan) -> Iterator[Hit]:
    for srv in plan.of_type("azurerm_mssql_server"):
        if srv.get("public_network_access_enabled") is True:
            yield srv, "public_network_access_enabled is true"


@rule(
    "PG107",
    "Linux VM allows password login",
    "medium",
    "azure",
    ["IA-2", "IA-5"],
    risk="Passwords can be guessed. SSH keys are much harder to break.",
    fix="Set disable_password_authentication = true and add an admin_ssh_key.",
)
def vm_password_login(plan: Plan) -> Iterator[Hit]:
    for vm in plan.of_type("azurerm_linux_virtual_machine"):
        if vm.known("disable_password_authentication") and vm.get("disable_password_authentication") is False:
            yield vm, "disable_password_authentication is false"
