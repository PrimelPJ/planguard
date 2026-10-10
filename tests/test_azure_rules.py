import unittest

from .helpers import hits, make_plan


def nsg_rule(**overrides):
    rule = {
        "name": "r",
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "source_address_prefix": "*",
        "source_address_prefixes": [],
        "destination_port_range": "22",
        "destination_port_ranges": [],
    }
    rule.update(overrides)
    return make_plan(("azurerm_network_security_rule", "r", rule))


class StorageTest(unittest.TestCase):
    def test_https_new_and_old_names(self):
        self.assertEqual(hits(make_plan(("azurerm_storage_account", "s", {"https_traffic_only_enabled": False})), "PG101"), ["azurerm_storage_account.s"])
        self.assertEqual(hits(make_plan(("azurerm_storage_account", "s", {"enable_https_traffic_only": False})), "PG101"), ["azurerm_storage_account.s"])
        self.assertEqual(hits(make_plan(("azurerm_storage_account", "s", {"https_traffic_only_enabled": True})), "PG101"), [])

    def test_tls(self):
        self.assertEqual(hits(make_plan(("azurerm_storage_account", "s", {"min_tls_version": "TLS1_1"})), "PG102"), ["azurerm_storage_account.s"])
        self.assertEqual(hits(make_plan(("azurerm_storage_account", "s", {"min_tls_version": "TLS1_2"})), "PG102"), [])

    def test_public_blobs(self):
        self.assertEqual(hits(make_plan(("azurerm_storage_account", "s", {"allow_nested_items_to_be_public": True})), "PG103"), ["azurerm_storage_account.s"])
        self.assertEqual(hits(make_plan(("azurerm_storage_container", "c", {"container_access_type": "blob"})), "PG103"), ["azurerm_storage_container.c"])
        self.assertEqual(hits(make_plan(("azurerm_storage_container", "c", {"container_access_type": "private"})), "PG103"), [])


class NsgTest(unittest.TestCase):
    def test_ssh_from_anywhere(self):
        self.assertEqual(hits(nsg_rule(), "PG104"), ["azurerm_network_security_rule.r"])

    def test_internet_tag_and_port_range(self):
        plan = nsg_rule(source_address_prefix="Internet", destination_port_range="3000-4000")
        self.assertEqual(hits(plan, "PG104"), ["azurerm_network_security_rule.r"])

    def test_star_port_and_prefix_lists(self):
        plan = nsg_rule(source_address_prefix=None, source_address_prefixes=["0.0.0.0/0"], destination_port_range=None, destination_port_ranges=["*"])
        self.assertEqual(hits(plan, "PG104"), ["azurerm_network_security_rule.r"])

    def test_not_flagged(self):
        self.assertEqual(hits(nsg_rule(source_address_prefix="10.0.0.0/8"), "PG104"), [])
        self.assertEqual(hits(nsg_rule(access="Deny"), "PG104"), [])
        self.assertEqual(hits(nsg_rule(direction="Outbound"), "PG104"), [])
        self.assertEqual(hits(nsg_rule(protocol="Udp"), "PG104"), [])
        self.assertEqual(hits(nsg_rule(destination_port_range="443"), "PG104"), [])

    def test_inline_rules_in_nsg(self):
        plan = make_plan(
            ("azurerm_network_security_group", "g", {"security_rule": [
                {"name": "web", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "source_address_prefix": "*", "destination_port_range": "443"},
                {"name": "rdp", "direction": "Inbound", "access": "Allow", "protocol": "*", "source_address_prefix": "*", "destination_port_range": "3389"},
            ]})
        )
        self.assertEqual(hits(plan, "PG104"), ["azurerm_network_security_group.g"])


class OtherAzureTest(unittest.TestCase):
    def test_key_vault(self):
        self.assertEqual(hits(make_plan(("azurerm_key_vault", "k", {"purge_protection_enabled": False})), "PG105"), ["azurerm_key_vault.k"])
        self.assertEqual(hits(make_plan(("azurerm_key_vault", "k", {"purge_protection_enabled": True})), "PG105"), [])

    def test_sql(self):
        self.assertEqual(hits(make_plan(("azurerm_mssql_server", "s", {"public_network_access_enabled": True})), "PG106"), ["azurerm_mssql_server.s"])
        self.assertEqual(hits(make_plan(("azurerm_mssql_server", "s", {"public_network_access_enabled": False})), "PG106"), [])

    def test_vm_password(self):
        self.assertEqual(hits(make_plan(("azurerm_linux_virtual_machine", "v", {"disable_password_authentication": False})), "PG107"), ["azurerm_linux_virtual_machine.v"])
        self.assertEqual(hits(make_plan(("azurerm_linux_virtual_machine", "v", {"disable_password_authentication": True})), "PG107"), [])


if __name__ == "__main__":
    unittest.main()
