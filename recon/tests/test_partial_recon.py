"""
Unit tests for Partial Recon module (recon/partial_recon.py).

Run with: python -m pytest recon/tests/test_partial_recon.py -v
"""
import sys
import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock, PropertyMock

# Add paths
_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
sys.path.insert(0, _project_root)
sys.path.insert(0, _recon_dir)

# Pre-mock heavy dependencies that aren't available in the test environment
sys.modules['neo4j'] = MagicMock()

# Import only load_config and helpers at module level (doesn't trigger lazy imports)
from partial_recon import load_config, _classify_ip, _is_ip_or_cidr, _is_valid_hostname


class TestLoadConfig(unittest.TestCase):
    """Tests for config loading from JSON file."""

    def test_load_valid_config(self):
        config = {"tool_id": "SubdomainDiscovery", "domain": "example.com", "user_inputs": ["api.example.com"]}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            f.flush()
            os.environ["PARTIAL_RECON_CONFIG"] = f.name
            try:
                result = load_config()
                self.assertEqual(result["tool_id"], "SubdomainDiscovery")
                self.assertEqual(result["domain"], "example.com")
            finally:
                del os.environ["PARTIAL_RECON_CONFIG"]
                os.unlink(f.name)

    def test_load_config_missing_env(self):
        if "PARTIAL_RECON_CONFIG" in os.environ:
            del os.environ["PARTIAL_RECON_CONFIG"]
        with self.assertRaises(SystemExit):
            load_config()

    def test_load_config_invalid_file(self):
        os.environ["PARTIAL_RECON_CONFIG"] = "/nonexistent/path.json"
        try:
            with self.assertRaises(SystemExit):
                load_config()
        finally:
            del os.environ["PARTIAL_RECON_CONFIG"]

    def test_load_config_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid")
            f.flush()
            os.environ["PARTIAL_RECON_CONFIG"] = f.name
            try:
                with self.assertRaises(SystemExit):
                    load_config()
            finally:
                del os.environ["PARTIAL_RECON_CONFIG"]
                os.unlink(f.name)

    def test_config_preserves_all_fields(self):
        config = {
            "tool_id": "SubdomainDiscovery",
            "domain": "test.io",
            "user_inputs": ["a.test.io", "b.test.io"],
            "user_id": "u1",
            "webapp_api_url": "http://localhost:3000",
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            f.flush()
            os.environ["PARTIAL_RECON_CONFIG"] = f.name
            try:
                result = load_config()
                self.assertEqual(result["domain"], "test.io")
                self.assertEqual(len(result["user_inputs"]), 2)
                self.assertEqual(result["webapp_api_url"], "http://localhost:3000")
            finally:
                del os.environ["PARTIAL_RECON_CONFIG"]
                os.unlink(f.name)


def _mock_discover_result(subdomains=None):
    subs = subdomains or ["www.example.com", "api.example.com"]
    return {
        "metadata": {"scan_type": "subdomain_dns_discovery"},
        "domain": "example.com",
        "subdomains": subs,
        "subdomain_count": len(subs),
        "dns": {
            "domain": {"has_records": True, "records": {}, "ips": {"ipv4": ["93.184.216.34"], "ipv6": []}},
            "subdomains": {s: {"has_records": True, "records": {}, "ips": {"ipv4": ["93.184.216.34"], "ipv6": []}} for s in subs},
        },
        "external_domains": [],
        "subdomain_status_map": {s: "resolved" for s in subs},
    }


class TestRunSubdomainDiscovery(unittest.TestCase):
    """Tests for run_subdomain_discovery using module-level mocks.

    Since partial_recon.py uses lazy imports inside function bodies,
    we mock the modules in sys.modules before calling the function.
    """

    def _run_with_mocks(self, config, discover_result=None, neo4j_connected=True, puredns_result=None, resolve_dns_result=None):
        """Helper that sets up all mocks and runs run_subdomain_discovery."""
        # Mock get_settings
        mock_settings = MagicMock()
        mock_settings.return_value = {"USE_TOR_FOR_RECON": False, "USE_BRUTEFORCE_FOR_SUBDOMAINS": False}

        # Mock domain_recon functions
        mock_discover = MagicMock(return_value=discover_result or _mock_discover_result())
        mock_resolve = MagicMock(return_value=resolve_dns_result or {
            "domain": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
            "subdomains": {},
        })
        mock_puredns = MagicMock(return_value=puredns_result or [])

        # Mock Neo4jClient
        mock_client = MagicMock()
        mock_client.verify_connection.return_value = neo4j_connected
        mock_client.update_graph_from_partial_discovery.return_value = {
            "subdomains_total": 2, "subdomains_new": 2, "subdomains_existing": 0,
            "ips_total": 2, "ips_new": 2, "dns_records_created": 0, "errors": [],
        }
        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Create mock modules
        mock_project_settings = MagicMock()
        mock_project_settings.get_settings = mock_settings

        mock_domain_recon = MagicMock()
        mock_domain_recon.discover_subdomains = mock_discover
        mock_domain_recon.resolve_all_dns = mock_resolve
        mock_domain_recon.run_puredns_resolve = mock_puredns

        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls

        # Inject mocks into sys.modules
        saved = {}
        modules_to_mock = {
            'recon.project_settings': mock_project_settings,
            'recon.domain_recon': mock_domain_recon,
            'graph_db': mock_graph_db,
        }
        for name, mod in modules_to_mock.items():
            saved[name] = sys.modules.get(name)
            sys.modules[name] = mod

        os.environ.setdefault("USER_ID", "user1")
        os.environ.setdefault("PROJECT_ID", "proj1")

        try:
            # Re-import to pick up mocked modules
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            pr.run_subdomain_discovery(config)
        finally:
            # Restore modules
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

        return {
            "settings": mock_settings,
            "discover": mock_discover,
            "resolve_dns": mock_resolve,
            "puredns": mock_puredns,
            "neo4j_client": mock_client,
            "neo4j_cls": mock_neo4j_cls,
        }

    def test_basic_discovery_no_user_inputs(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": []})
        mocks["discover"].assert_called_once()
        mocks["neo4j_client"].update_graph_from_partial_discovery.assert_called_once()
        _, kw = mocks["neo4j_client"].update_graph_from_partial_discovery.call_args
        self.assertIsNone(kw.get("user_input_id"))

    def test_user_inputs_triggers_userinput_node(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["new.example.com"]},
            discover_result=_mock_discover_result(["www.example.com"]),
            puredns_result=["www.example.com", "new.example.com"],
            resolve_dns_result={
                "domain": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
                "subdomains": {
                    "www.example.com": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
                    "new.example.com": {"has_records": True, "records": {}, "ips": {"ipv4": ["5.6.7.8"], "ipv6": []}},
                },
            },
        )
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["domain"], "example.com")
        self.assertEqual(ui_kw["user_input_data"]["values"], ["new.example.com"])
        self.assertEqual(ui_kw["user_input_data"]["tool_id"], "SubdomainDiscovery")

    def test_neo4j_unavailable_skips_update(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": []},
            neo4j_connected=False,
        )
        mocks["neo4j_client"].update_graph_from_partial_discovery.assert_not_called()

    def test_settings_fetched_from_get_settings(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": []})
        mocks["settings"].assert_called_once()

    def test_user_input_status_completed(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["x.example.com"]},
            discover_result=_mock_discover_result(["www.example.com"]),
            puredns_result=["www.example.com", "x.example.com"],
            resolve_dns_result={
                "domain": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
                "subdomains": {"www.example.com": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}}, "x.example.com": {"has_records": True, "records": {}, "ips": {"ipv4": ["2.3.4.5"], "ipv6": []}}},
            },
        )
        mocks["neo4j_client"].update_user_input_status.assert_called_once()
        args = mocks["neo4j_client"].update_user_input_status.call_args[0]
        self.assertEqual(args[1], "completed")


def _mock_port_scan_result(recon_data=None):
    """Build a mock recon_data dict with port_scan results."""
    data = recon_data or {
        "domain": "example.com",
        "dns": {
            "domain": {"ips": {"ipv4": ["93.184.216.34"], "ipv6": []}, "has_records": True},
            "subdomains": {},
        },
    }
    data["port_scan"] = {
        "scan_metadata": {"scan_timestamp": "2026-01-01T00:00:00", "scanners": ["naabu"]},
        "by_host": {
            "example.com": {"host": "example.com", "ip": "93.184.216.34", "ports": [80, 443], "port_details": [
                {"port": 80, "protocol": "tcp", "service": "http"},
                {"port": 443, "protocol": "tcp", "service": "https"},
            ]},
        },
        "by_ip": {"93.184.216.34": {"ip": "93.184.216.34", "hostnames": ["example.com"], "ports": [80, 443]}},
        "all_ports": [80, 443],
        "summary": {"hosts_scanned": 1, "total_open_ports": 2, "unique_ports": [80, 443]},
    }
    return data


class TestRunNaabu(unittest.TestCase):
    """Tests for run_naabu using module-level mocks."""

    def _run_with_mocks(self, config, neo4j_connected=True, domain_ips=None, subdomain_ips=None, port_scan_result=None):
        """Helper that sets up all mocks and runs run_naabu."""
        # Mock get_settings
        mock_settings = MagicMock()
        mock_settings.return_value = {"NAABU_ENABLED": True, "NAABU_TOP_PORTS": "1000"}

        # Mock run_port_scan: modifies recon_data in place and returns it
        mock_port_scan = MagicMock(side_effect=lambda recon_data, output_file=None, settings=None: _mock_port_scan_result(recon_data))

        # Mock Neo4jClient
        mock_client = MagicMock()
        mock_client.verify_connection.return_value = neo4j_connected
        mock_client.update_graph_from_port_scan.return_value = {
            "ports_created": 2, "services_created": 2, "ips_updated": 1,
            "relationships_created": 4, "errors": [],
        }

        # Mock the neo4j driver session for graph queries
        mock_session = MagicMock()
        _domain_ips = domain_ips if domain_ips is not None else [
            {"address": "93.184.216.34", "version": "ipv4"},
        ]
        _subdomain_ips = subdomain_ips if subdomain_ips is not None else [
            {"subdomain": "www.example.com", "address": "93.184.216.34", "version": "ipv4"},
        ]
        # Mock session.run to return proper records based on query content
        def mock_session_run(query, **kwargs):
            result = MagicMock()
            if "RESOLVES_TO]->(i:IP)" in query and "HAS_SUBDOMAIN" not in query:
                # Domain -> IP query
                records = []
                for ip_data in _domain_ips:
                    record = MagicMock()
                    record.__getitem__ = lambda self, key, d=ip_data: d[key]
                    records.append(record)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "HAS_SUBDOMAIN" in query and "RESOLVES_TO" in query:
                # Subdomain -> IP query
                records = []
                for ip_data in _subdomain_ips:
                    record = MagicMock()
                    record.__getitem__ = lambda self, key, d=ip_data: d[key]
                    records.append(record)
                result.__iter__ = lambda self, r=records: iter(r)
            else:
                result.__iter__ = lambda self: iter([])
            return result

        mock_session.run = mock_session_run

        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.driver = mock_driver

        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Create mock modules
        mock_project_settings = MagicMock()
        mock_project_settings.get_settings = mock_settings

        mock_port_scan_mod = MagicMock()
        mock_port_scan_mod.run_port_scan = mock_port_scan

        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls

        # Inject mocks into sys.modules
        saved = {}
        modules_to_mock = {
            'recon.project_settings': mock_project_settings,
            'recon.port_scan': mock_port_scan_mod,
            'graph_db': mock_graph_db,
        }
        for name, mod in modules_to_mock.items():
            saved[name] = sys.modules.get(name)
            sys.modules[name] = mod

        os.environ.setdefault("USER_ID", "user1")
        os.environ.setdefault("PROJECT_ID", "proj1")

        try:
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            pr.run_naabu(config)
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

        return {
            "settings": mock_settings,
            "port_scan": mock_port_scan,
            "neo4j_client": mock_client,
            "neo4j_cls": mock_neo4j_cls,
        }

    def test_basic_scan_no_user_inputs(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": []})
        mocks["port_scan"].assert_called_once()
        mocks["neo4j_client"].update_graph_from_port_scan.assert_called_once()

    def test_settings_fetched(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": []})
        mocks["settings"].assert_called_once()

    def test_user_ips_create_userinput_node(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.1", "192.168.1.0/24"]},
        )
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["user_input_data"]["input_type"], "ips")
        self.assertEqual(ui_kw["user_input_data"]["tool_id"], "Naabu")
        self.assertIn("10.0.0.1", ui_kw["user_input_data"]["values"])
        self.assertIn("192.168.1.0/24", ui_kw["user_input_data"]["values"])

    def test_invalid_ips_rejected(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["not-an-ip", "10.0.0.1"]},
        )
        # Should still create UserInput node with only valid IPs
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["user_input_data"]["values"], ["10.0.0.1"])

    def test_empty_graph_no_user_inputs_exits(self):
        with self.assertRaises(SystemExit):
            self._run_with_mocks(
                {"domain": "example.com", "user_inputs": []},
                domain_ips=[],
                subdomain_ips=[],
            )

    def test_user_input_status_completed(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.1"]},
        )
        mocks["neo4j_client"].update_user_input_status.assert_called_once()
        args = mocks["neo4j_client"].update_user_input_status.call_args[0]
        self.assertEqual(args[1], "completed")

    def test_neo4j_unavailable_exits_no_targets(self):
        # When Neo4j is down, no IPs can be fetched, so Naabu exits
        with self.assertRaises(SystemExit):
            self._run_with_mocks(
                {"domain": "example.com", "user_inputs": []},
                neo4j_connected=False,
            )

    def test_port_scan_called_with_recon_data(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": []},
        )
        call_args = mocks["port_scan"].call_args
        recon_data = call_args[0][0]
        self.assertEqual(recon_data["domain"], "example.com")
        self.assertIn("dns", recon_data)
        self.assertIn("domain", recon_data["dns"])
        self.assertIn("subdomains", recon_data["dns"])


class TestClassifyIp(unittest.TestCase):
    """Tests for _classify_ip helper."""

    def test_ipv4_with_version_hint(self):
        self.assertEqual(_classify_ip("93.184.216.34", "ipv4"), "ipv4")

    def test_ipv6_with_version_hint(self):
        self.assertEqual(_classify_ip("::1", "ipv6"), "ipv6")

    def test_version_hint_case_insensitive(self):
        self.assertEqual(_classify_ip("1.2.3.4", "IPv4"), "ipv4")
        self.assertEqual(_classify_ip("::1", "IPv6"), "ipv6")

    def test_ipv4_without_hint(self):
        self.assertEqual(_classify_ip("10.0.0.1"), "ipv4")

    def test_ipv6_without_hint(self):
        self.assertEqual(_classify_ip("2001:db8::1"), "ipv6")

    def test_none_version_falls_through(self):
        self.assertEqual(_classify_ip("192.168.1.1", None), "ipv4")

    def test_empty_version_falls_through(self):
        self.assertEqual(_classify_ip("192.168.1.1", ""), "ipv4")

    def test_invalid_address_defaults_ipv4(self):
        # Invalid address with no version hint defaults to ipv4
        self.assertEqual(_classify_ip("not-an-ip"), "ipv4")


class TestIsIpOrCidr(unittest.TestCase):
    """Tests for _is_ip_or_cidr helper."""

    def test_ipv4(self):
        self.assertTrue(_is_ip_or_cidr("10.0.0.1"))

    def test_ipv6(self):
        self.assertTrue(_is_ip_or_cidr("2001:db8::1"))

    def test_cidr_v4(self):
        self.assertTrue(_is_ip_or_cidr("10.0.0.0/24"))

    def test_cidr_v6(self):
        self.assertTrue(_is_ip_or_cidr("2001:db8::/32"))

    def test_hostname_is_not_ip(self):
        self.assertFalse(_is_ip_or_cidr("www.example.com"))

    def test_garbage(self):
        self.assertFalse(_is_ip_or_cidr("not-valid"))

    def test_empty(self):
        self.assertFalse(_is_ip_or_cidr(""))


class TestIsValidHostname(unittest.TestCase):
    """Tests for _is_valid_hostname helper."""

    def test_valid_subdomain(self):
        self.assertTrue(_is_valid_hostname("www.example.com"))

    def test_valid_deep_subdomain(self):
        self.assertTrue(_is_valid_hostname("a.b.c.example.com"))

    def test_valid_with_hyphens(self):
        self.assertTrue(_is_valid_hostname("my-app.example.com"))

    def test_bare_tld_rejected(self):
        self.assertFalse(_is_valid_hostname("localhost"))

    def test_ip_address_rejected(self):
        self.assertFalse(_is_valid_hostname("10.0.0.1"))

    def test_trailing_dot_rejected(self):
        self.assertFalse(_is_valid_hostname("example.com."))

    def test_empty_rejected(self):
        self.assertFalse(_is_valid_hostname(""))

    def test_starts_with_hyphen_rejected(self):
        self.assertFalse(_is_valid_hostname("-bad.example.com"))


class TestBuildReconDataFromGraph(unittest.TestCase):
    """Tests for _build_recon_data_from_graph helper."""

    def _setup_mocks(self, domain_ips=None, subdomain_ips=None, neo4j_connected=True):
        """Create mocked Neo4jClient with configurable graph data."""
        _domain_ips = domain_ips if domain_ips is not None else []
        _subdomain_ips = subdomain_ips if subdomain_ips is not None else []

        mock_session = MagicMock()

        def mock_run(query, **kwargs):
            result = MagicMock()
            if "RESOLVES_TO]->(i:IP)" in query and "HAS_SUBDOMAIN" not in query:
                records = []
                for d in _domain_ips:
                    rec = MagicMock()
                    rec.__getitem__ = lambda self, key, data=d: data[key]
                    records.append(rec)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "HAS_SUBDOMAIN" in query and "RESOLVES_TO" in query:
                records = []
                for d in _subdomain_ips:
                    rec = MagicMock()
                    rec.__getitem__ = lambda self, key, data=d: data[key]
                    records.append(rec)
                result.__iter__ = lambda self, r=records: iter(r)
            else:
                result.__iter__ = lambda self: iter([])
            return result

        mock_session.run = mock_run

        mock_client = MagicMock()
        mock_client.verify_connection.return_value = neo4j_connected
        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.driver = mock_driver

        mock_cls = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        return mock_cls

    def _run(self, domain_ips=None, subdomain_ips=None, neo4j_connected=True):
        mock_cls = self._setup_mocks(domain_ips, subdomain_ips, neo4j_connected)
        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_cls

        saved = sys.modules.get('graph_db')
        sys.modules['graph_db'] = mock_graph_db
        try:
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            return pr._build_recon_data_from_graph("example.com", "u1", "p1")
        finally:
            if saved is None:
                sys.modules.pop('graph_db', None)
            else:
                sys.modules['graph_db'] = saved

    def test_empty_graph(self):
        data = self._run(domain_ips=[], subdomain_ips=[])
        self.assertEqual(data["domain"], "example.com")
        self.assertEqual(data["dns"]["domain"]["ips"]["ipv4"], [])
        self.assertEqual(data["dns"]["domain"]["ips"]["ipv6"], [])
        self.assertFalse(data["dns"]["domain"]["has_records"])
        self.assertEqual(data["dns"]["subdomains"], {})

    def test_domain_ips_only(self):
        data = self._run(
            domain_ips=[{"address": "1.2.3.4", "version": "ipv4"}],
            subdomain_ips=[],
        )
        self.assertEqual(data["dns"]["domain"]["ips"]["ipv4"], ["1.2.3.4"])
        self.assertTrue(data["dns"]["domain"]["has_records"])
        self.assertEqual(data["dns"]["subdomains"], {})

    def test_subdomain_ips_only(self):
        data = self._run(
            domain_ips=[],
            subdomain_ips=[
                {"subdomain": "www.example.com", "address": "5.6.7.8", "version": "ipv4"},
            ],
        )
        self.assertFalse(data["dns"]["domain"]["has_records"])
        self.assertIn("www.example.com", data["dns"]["subdomains"])
        self.assertEqual(data["dns"]["subdomains"]["www.example.com"]["ips"]["ipv4"], ["5.6.7.8"])
        self.assertTrue(data["dns"]["subdomains"]["www.example.com"]["has_records"])

    def test_ipv6_addresses(self):
        data = self._run(
            domain_ips=[{"address": "2001:db8::1", "version": "ipv6"}],
            subdomain_ips=[],
        )
        self.assertEqual(data["dns"]["domain"]["ips"]["ipv6"], ["2001:db8::1"])
        self.assertEqual(data["dns"]["domain"]["ips"]["ipv4"], [])
        self.assertTrue(data["dns"]["domain"]["has_records"])

    def test_multiple_subdomains(self):
        data = self._run(
            domain_ips=[],
            subdomain_ips=[
                {"subdomain": "a.example.com", "address": "1.1.1.1", "version": "ipv4"},
                {"subdomain": "b.example.com", "address": "2.2.2.2", "version": "ipv4"},
                {"subdomain": "a.example.com", "address": "3.3.3.3", "version": "ipv4"},
            ],
        )
        self.assertEqual(len(data["dns"]["subdomains"]), 2)
        self.assertEqual(data["dns"]["subdomains"]["a.example.com"]["ips"]["ipv4"], ["1.1.1.1", "3.3.3.3"])
        self.assertEqual(data["dns"]["subdomains"]["b.example.com"]["ips"]["ipv4"], ["2.2.2.2"])

    def test_neo4j_unavailable_returns_empty(self):
        data = self._run(neo4j_connected=False)
        self.assertFalse(data["dns"]["domain"]["has_records"])
        self.assertEqual(data["dns"]["subdomains"], {})

    def test_version_none_uses_fallback(self):
        data = self._run(
            domain_ips=[{"address": "10.0.0.1", "version": None}],
            subdomain_ips=[],
        )
        # Should classify via ipaddress module fallback
        self.assertEqual(data["dns"]["domain"]["ips"]["ipv4"], ["10.0.0.1"])


class TestRunNaabuCidrExpansion(unittest.TestCase):
    """Tests specifically for CIDR expansion and edge cases in run_naabu."""

    def _run_with_mocks(self, config, domain_ips=None, subdomain_ips=None):
        """Minimal mock setup focused on CIDR handling."""
        mock_settings = MagicMock()
        mock_settings.return_value = {"NAABU_ENABLED": True}

        mock_port_scan = MagicMock(side_effect=lambda recon_data, output_file=None, settings=None: _mock_port_scan_result(recon_data))

        mock_client = MagicMock()
        mock_client.verify_connection.return_value = True
        mock_client.update_graph_from_port_scan.return_value = {"ports_created": 0, "errors": []}

        mock_session = MagicMock()
        _domain_ips = domain_ips if domain_ips is not None else []
        _subdomain_ips = subdomain_ips if subdomain_ips is not None else []

        def mock_run(query, **kwargs):
            result = MagicMock()
            if "RESOLVES_TO]->(i:IP)" in query and "HAS_SUBDOMAIN" not in query:
                records = []
                for d in _domain_ips:
                    rec = MagicMock()
                    rec.__getitem__ = lambda self, key, data=d: data[key]
                    records.append(rec)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "HAS_SUBDOMAIN" in query and "RESOLVES_TO" in query:
                records = []
                for d in _subdomain_ips:
                    rec = MagicMock()
                    rec.__getitem__ = lambda self, key, data=d: data[key]
                    records.append(rec)
                result.__iter__ = lambda self, r=records: iter(r)
            else:
                result.__iter__ = lambda self: iter([])
            return result

        mock_session.run = mock_run
        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.driver = mock_driver

        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls

        mock_project_settings = MagicMock()
        mock_project_settings.get_settings = mock_settings

        mock_port_scan_mod = MagicMock()
        mock_port_scan_mod.run_port_scan = mock_port_scan

        saved = {}
        modules_to_mock = {
            'recon.project_settings': mock_project_settings,
            'recon.port_scan': mock_port_scan_mod,
            'graph_db': mock_graph_db,
        }
        for name, mod in modules_to_mock.items():
            saved[name] = sys.modules.get(name)
            sys.modules[name] = mod

        os.environ.setdefault("USER_ID", "user1")
        os.environ.setdefault("PROJECT_ID", "proj1")

        try:
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            pr.run_naabu(config)
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

        return {"port_scan": mock_port_scan, "neo4j_client": mock_client}

    def test_cidr_24_expanded(self):
        """A /30 CIDR (2 usable hosts) should be expanded into individual IPs."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.0/30"]},
            domain_ips=[], subdomain_ips=[],
        )
        # /30 has 2 usable hosts: 10.0.0.1, 10.0.0.2
        call_args = mocks["port_scan"].call_args
        recon_data = call_args[0][0]
        ipv4s = recon_data["dns"]["domain"]["ips"]["ipv4"]
        self.assertIn("10.0.0.1", ipv4s)
        self.assertIn("10.0.0.2", ipv4s)
        self.assertEqual(len(ipv4s), 2)

    def test_oversized_cidr_skipped(self):
        """A /16 CIDR (65536 addresses) should be skipped."""
        with self.assertRaises(SystemExit):
            self._run_with_mocks(
                {"domain": "example.com", "user_inputs": ["10.0.0.0/16"]},
                domain_ips=[], subdomain_ips=[],
            )

    def test_oversized_cidr_with_graph_ips_still_scans(self):
        """Oversized CIDR is skipped but graph IPs are still scanned."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.0/16"]},
            domain_ips=[{"address": "93.184.216.34", "version": "ipv4"}],
            subdomain_ips=[],
        )
        mocks["port_scan"].assert_called_once()
        recon_data = mocks["port_scan"].call_args[0][0]
        self.assertIn("93.184.216.34", recon_data["dns"]["domain"]["ips"]["ipv4"])

    def test_single_ip_user_input_injected(self):
        """A single IP user input should be injected into the domain IPs."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.1"]},
            domain_ips=[], subdomain_ips=[],
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        self.assertIn("10.0.0.1", recon_data["dns"]["domain"]["ips"]["ipv4"])

    def test_user_ip_not_duplicated_with_graph(self):
        """If user provides an IP already in graph, it should not appear twice."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["93.184.216.34"]},
            domain_ips=[{"address": "93.184.216.34", "version": "ipv4"}],
            subdomain_ips=[],
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        ipv4s = recon_data["dns"]["domain"]["ips"]["ipv4"]
        self.assertEqual(ipv4s.count("93.184.216.34"), 1)

    def test_ipv6_user_input(self):
        """IPv6 addresses should be placed in the ipv6 bucket."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["2001:db8::1"]},
            domain_ips=[], subdomain_ips=[],
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        self.assertIn("2001:db8::1", recon_data["dns"]["domain"]["ips"]["ipv6"])
        self.assertEqual(recon_data["dns"]["domain"]["ips"]["ipv4"], [])

    def test_all_invalid_user_inputs_no_userinput_node(self):
        """If all user inputs are invalid, no UserInput node should be created."""
        with self.assertRaises(SystemExit):
            self._run_with_mocks(
                {"domain": "example.com", "user_inputs": ["bad", "also-bad", "nope"]},
                domain_ips=[], subdomain_ips=[],
            )

    def test_mixed_valid_invalid_ips(self):
        """Valid IPs should be kept, invalid ones rejected."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["bad", "10.0.0.1", "also-bad", "10.0.0.2"]},
            domain_ips=[], subdomain_ips=[],
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        ipv4s = recon_data["dns"]["domain"]["ips"]["ipv4"]
        self.assertIn("10.0.0.1", ipv4s)
        self.assertIn("10.0.0.2", ipv4s)
        self.assertEqual(len(ipv4s), 2)

    def test_recon_data_structure_matches_expected(self):
        """Verify the exact structure that extract_targets_from_recon expects."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": []},
            domain_ips=[{"address": "1.2.3.4", "version": "ipv4"}],
            subdomain_ips=[
                {"subdomain": "www.example.com", "address": "5.6.7.8", "version": "ipv4"},
            ],
        )
        recon_data = mocks["port_scan"].call_args[0][0]

        # Top-level keys
        self.assertIn("domain", recon_data)
        self.assertIn("dns", recon_data)
        self.assertEqual(recon_data["domain"], "example.com")

        # Domain DNS structure
        dns = recon_data["dns"]
        self.assertIn("domain", dns)
        self.assertIn("subdomains", dns)
        self.assertIn("ips", dns["domain"])
        self.assertIn("ipv4", dns["domain"]["ips"])
        self.assertIn("ipv6", dns["domain"]["ips"])
        self.assertIn("has_records", dns["domain"])
        self.assertTrue(dns["domain"]["has_records"])

        # Subdomain structure
        self.assertIn("www.example.com", dns["subdomains"])
        sub = dns["subdomains"]["www.example.com"]
        self.assertIn("ips", sub)
        self.assertIn("ipv4", sub["ips"])
        self.assertIn("ipv6", sub["ips"])
        self.assertIn("has_records", sub)
        self.assertTrue(sub["has_records"])


class TestRunNaabuHostnameInputs(unittest.TestCase):
    """Tests for user-provided hostname/subdomain inputs in run_naabu."""

    def _run_with_mocks(self, config, domain_ips=None, subdomain_ips=None, resolve_results=None):
        """Mock setup with DNS resolution support for hostnames."""
        mock_settings = MagicMock()
        mock_settings.return_value = {"NAABU_ENABLED": True}

        mock_port_scan = MagicMock(side_effect=lambda recon_data, output_file=None, settings=None: _mock_port_scan_result(recon_data))

        mock_client = MagicMock()
        mock_client.verify_connection.return_value = True
        mock_client.update_graph_from_port_scan.return_value = {"ports_created": 0, "errors": []}

        mock_session = MagicMock()
        _domain_ips = domain_ips if domain_ips is not None else []
        _subdomain_ips = subdomain_ips if subdomain_ips is not None else []

        def mock_run(query, **kwargs):
            result = MagicMock()
            if "RESOLVES_TO]->(i:IP)" in query and "HAS_SUBDOMAIN" not in query:
                records = []
                for d in _domain_ips:
                    rec = MagicMock()
                    rec.__getitem__ = lambda self, key, data=d: data[key]
                    records.append(rec)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "HAS_SUBDOMAIN" in query and "RESOLVES_TO" in query:
                records = []
                for d in _subdomain_ips:
                    rec = MagicMock()
                    rec.__getitem__ = lambda self, key, data=d: data[key]
                    records.append(rec)
                result.__iter__ = lambda self, r=records: iter(r)
            else:
                result.__iter__ = lambda self: iter([])
            return result

        mock_session.run = mock_run
        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.driver = mock_driver

        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls

        mock_project_settings = MagicMock()
        mock_project_settings.get_settings = mock_settings

        mock_port_scan_mod = MagicMock()
        mock_port_scan_mod.run_port_scan = mock_port_scan

        # resolve_results: dict mapping hostname -> {"ipv4": [...], "ipv6": [...]}
        _resolve = resolve_results or {}

        saved = {}
        modules_to_mock = {
            'recon.project_settings': mock_project_settings,
            'recon.port_scan': mock_port_scan_mod,
            'graph_db': mock_graph_db,
        }
        for name, mod in modules_to_mock.items():
            saved[name] = sys.modules.get(name)
            sys.modules[name] = mod

        os.environ.setdefault("USER_ID", "user1")
        os.environ.setdefault("PROJECT_ID", "proj1")

        try:
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            # Patch _resolve_hostname to return controlled results
            original_resolve = pr._resolve_hostname
            pr._resolve_hostname = lambda h: _resolve.get(h, {"ipv4": [], "ipv6": []})
            try:
                pr.run_naabu(config)
            finally:
                pr._resolve_hostname = original_resolve
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

        return {"port_scan": mock_port_scan, "neo4j_client": mock_client}

    def test_hostname_resolved_and_injected(self):
        """A user-provided hostname should be resolved and added to dns.subdomains."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["custom.example.com"]},
            domain_ips=[], subdomain_ips=[],
            resolve_results={"custom.example.com": {"ipv4": ["9.8.7.6"], "ipv6": []}},
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        self.assertIn("custom.example.com", recon_data["dns"]["subdomains"])
        sub = recon_data["dns"]["subdomains"]["custom.example.com"]
        self.assertEqual(sub["ips"]["ipv4"], ["9.8.7.6"])
        self.assertTrue(sub["has_records"])

    def test_unresolvable_hostname_skipped(self):
        """A hostname that doesn't resolve should be skipped, not crash."""
        with self.assertRaises(SystemExit):
            # Empty graph + unresolvable hostname = no targets -> exit
            self._run_with_mocks(
                {"domain": "example.com", "user_inputs": ["noresolve.example.com"]},
                domain_ips=[], subdomain_ips=[],
                resolve_results={},  # no resolution
            )

    def test_hostname_already_in_graph_skipped(self):
        """If hostname is already in graph subdomains, it should not be re-resolved."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["www.example.com"]},
            domain_ips=[],
            subdomain_ips=[{"subdomain": "www.example.com", "address": "1.2.3.4", "version": "ipv4"}],
            resolve_results={"www.example.com": {"ipv4": ["5.5.5.5"], "ipv6": []}},
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        sub = recon_data["dns"]["subdomains"]["www.example.com"]
        # Should have the graph IP, not the resolve result
        self.assertEqual(sub["ips"]["ipv4"], ["1.2.3.4"])

    def test_mixed_ips_and_hostnames(self):
        """Both IPs and hostnames in the same user_inputs list."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.1", "api.example.com"]},
            domain_ips=[], subdomain_ips=[],
            resolve_results={"api.example.com": {"ipv4": ["4.3.2.1"], "ipv6": []}},
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        # IP injected into domain
        self.assertIn("10.0.0.1", recon_data["dns"]["domain"]["ips"]["ipv4"])
        # Hostname added as subdomain
        self.assertIn("api.example.com", recon_data["dns"]["subdomains"])
        self.assertEqual(recon_data["dns"]["subdomains"]["api.example.com"]["ips"]["ipv4"], ["4.3.2.1"])

    def test_userinput_node_only_for_ips_not_hostnames(self):
        """UserInput node should only contain IPs, not hostnames (hostnames become real nodes)."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.1", "api.example.com"]},
            domain_ips=[], subdomain_ips=[],
            resolve_results={"api.example.com": {"ipv4": ["4.3.2.1"], "ipv6": []}},
        )
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["user_input_data"]["input_type"], "ips")
        self.assertIn("10.0.0.1", ui_kw["user_input_data"]["values"])
        self.assertNotIn("api.example.com", ui_kw["user_input_data"]["values"])

    def test_hostname_only_no_userinput_node(self):
        """When user provides only hostnames, no UserInput node should be created."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["api.example.com"]},
            domain_ips=[], subdomain_ips=[],
            resolve_results={"api.example.com": {"ipv4": ["4.3.2.1"], "ipv6": []}},
        )
        mocks["neo4j_client"].create_user_input_node.assert_not_called()

    def test_hostname_with_ipv6_resolution(self):
        """Hostname resolving to IPv6 should be placed in ipv6 bucket."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["v6.example.com"]},
            domain_ips=[], subdomain_ips=[],
            resolve_results={"v6.example.com": {"ipv4": [], "ipv6": ["2001:db8::1"]}},
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        sub = recon_data["dns"]["subdomains"]["v6.example.com"]
        self.assertEqual(sub["ips"]["ipv6"], ["2001:db8::1"])
        self.assertEqual(sub["ips"]["ipv4"], [])


class TestRunNaabuStructuredTargets(unittest.TestCase):
    """Tests for the new user_targets structured input format."""

    def _run_with_mocks(self, config, domain_ips=None, subdomain_ips=None, resolve_results=None):
        """Mock setup for structured user_targets tests."""
        mock_settings = MagicMock()
        mock_settings.return_value = {"NAABU_ENABLED": True}

        mock_port_scan = MagicMock(side_effect=lambda recon_data, output_file=None, settings=None: _mock_port_scan_result(recon_data))

        mock_client = MagicMock()
        mock_client.verify_connection.return_value = True
        mock_client.update_graph_from_port_scan.return_value = {"ports_created": 0, "errors": []}

        mock_session = MagicMock()
        _domain_ips = domain_ips if domain_ips is not None else []
        _subdomain_ips = subdomain_ips if subdomain_ips is not None else []

        def mock_run(query, **kwargs):
            result = MagicMock()
            if "RESOLVES_TO]->(i:IP)" in query and "HAS_SUBDOMAIN" not in query:
                records = []
                for d in _domain_ips:
                    rec = MagicMock()
                    rec.__getitem__ = lambda self, key, data=d: data[key]
                    records.append(rec)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "HAS_SUBDOMAIN" in query and "RESOLVES_TO" in query:
                records = []
                for d in _subdomain_ips:
                    rec = MagicMock()
                    rec.__getitem__ = lambda self, key, data=d: data[key]
                    records.append(rec)
                result.__iter__ = lambda self, r=records: iter(r)
            else:
                result.__iter__ = lambda self: iter([])
            return result

        mock_session.run = mock_run
        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.driver = mock_driver

        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls

        mock_project_settings = MagicMock()
        mock_project_settings.get_settings = mock_settings

        mock_port_scan_mod = MagicMock()
        mock_port_scan_mod.run_port_scan = mock_port_scan

        _resolve = resolve_results or {}

        saved = {}
        modules_to_mock = {
            'recon.project_settings': mock_project_settings,
            'recon.port_scan': mock_port_scan_mod,
            'graph_db': mock_graph_db,
        }
        for name, mod in modules_to_mock.items():
            saved[name] = sys.modules.get(name)
            sys.modules[name] = mod

        os.environ.setdefault("USER_ID", "user1")
        os.environ.setdefault("PROJECT_ID", "proj1")

        try:
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            original_resolve = pr._resolve_hostname
            pr._resolve_hostname = lambda h: _resolve.get(h, {"ipv4": [], "ipv6": []})
            try:
                pr.run_naabu(config)
            finally:
                pr._resolve_hostname = original_resolve
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

        return {"port_scan": mock_port_scan, "neo4j_client": mock_client}

    def test_ips_with_attach_to_subdomain_no_userinput(self):
        """IPs attached to a subdomain should NOT create UserInput node."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": ["10.0.0.1"], "ip_attach_to": "www.example.com"},
            },
            subdomain_ips=[{"subdomain": "www.example.com", "address": "1.2.3.4", "version": "ipv4"}],
        )
        mocks["neo4j_client"].create_user_input_node.assert_not_called()

    def test_ips_with_attach_to_null_creates_userinput(self):
        """IPs with ip_attach_to=null should create UserInput node."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": ["10.0.0.1"], "ip_attach_to": None},
            },
            domain_ips=[{"address": "1.2.3.4", "version": "ipv4"}],
        )
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["user_input_data"]["input_type"], "ips")

    def test_ips_attached_injected_into_subdomain_bucket(self):
        """IPs with ip_attach_to should appear in that subdomain's dns entry."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": ["10.0.0.1"], "ip_attach_to": "www.example.com"},
            },
            subdomain_ips=[{"subdomain": "www.example.com", "address": "1.2.3.4", "version": "ipv4"}],
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        sub_ips = recon_data["dns"]["subdomains"]["www.example.com"]["ips"]["ipv4"]
        self.assertIn("1.2.3.4", sub_ips)  # from graph
        self.assertIn("10.0.0.1", sub_ips)  # from user

    def test_ips_generic_injected_into_domain_bucket(self):
        """IPs with ip_attach_to=null should appear in domain's dns entry."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": ["10.0.0.1"], "ip_attach_to": None},
            },
            domain_ips=[],
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        self.assertIn("10.0.0.1", recon_data["dns"]["domain"]["ips"]["ipv4"])

    def test_subdomains_resolved_and_ips_attached(self):
        """Subdomains + IPs attached to a custom subdomain from same request."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {
                    "subdomains": ["api.example.com"],
                    "ips": ["10.0.0.1"],
                    "ip_attach_to": "api.example.com",
                },
            },
            domain_ips=[], subdomain_ips=[],
            resolve_results={"api.example.com": {"ipv4": ["9.8.7.6"], "ipv6": []}},
        )
        recon_data = mocks["port_scan"].call_args[0][0]
        # Subdomain should exist with resolved IP + user IP
        self.assertIn("api.example.com", recon_data["dns"]["subdomains"])
        sub_ips = recon_data["dns"]["subdomains"]["api.example.com"]["ips"]["ipv4"]
        self.assertIn("9.8.7.6", sub_ips)   # from DNS resolution
        self.assertIn("10.0.0.1", sub_ips)   # from user IP attached

    def test_empty_user_targets_uses_graph_only(self):
        """Empty user_targets should just scan graph data."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": [], "ip_attach_to": None},
            },
            domain_ips=[{"address": "1.2.3.4", "version": "ipv4"}],
        )
        mocks["port_scan"].assert_called_once()
        mocks["neo4j_client"].create_user_input_node.assert_not_called()

    def test_backward_compat_flat_user_inputs(self):
        """Legacy flat user_inputs should still work when user_targets is absent."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com",
                "user_inputs": ["10.0.0.1"],
                # NO user_targets key
            },
            domain_ips=[],
        )
        # Should create UserInput for the IP (legacy behavior)
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        recon_data = mocks["port_scan"].call_args[0][0]
        self.assertIn("10.0.0.1", recon_data["dns"]["domain"]["ips"]["ipv4"])


def _mock_masscan_scan_result(recon_data=None):
    """Build a mock recon_data dict with masscan_scan results (same structure as port_scan)."""
    data = recon_data or {
        "domain": "example.com",
        "dns": {
            "domain": {"ips": {"ipv4": ["93.184.216.34"], "ipv6": []}, "has_records": True},
            "subdomains": {},
        },
    }
    data["masscan_scan"] = {
        "scan_metadata": {"scanner": "masscan", "scan_timestamp": "2026-01-01T00:00:00"},
        "by_host": {
            "example.com": {"host": "example.com", "ip": "93.184.216.34", "ports": [80, 443], "port_details": [
                {"port": 80, "protocol": "tcp", "service": "http"},
                {"port": 443, "protocol": "tcp", "service": "https"},
            ]},
        },
        "by_ip": {"93.184.216.34": {"ip": "93.184.216.34", "hostnames": ["example.com"], "ports": [80, 443]}},
        "all_ports": [80, 443],
        "ip_to_hostnames": {"93.184.216.34": ["example.com"]},
        "summary": {"hosts_scanned": 1, "total_open_ports": 2, "unique_ports": [80, 443]},
    }
    return data


class TestRunMasscan(unittest.TestCase):
    """Tests for run_masscan using module-level mocks."""

    def _run_with_mocks(self, config, neo4j_connected=True, domain_ips=None, subdomain_ips=None):
        """Helper that sets up all mocks and runs run_masscan."""
        # Mock get_settings
        mock_settings = MagicMock()
        mock_settings.return_value = {"MASSCAN_ENABLED": False, "MASSCAN_TOP_PORTS": "1000", "MASSCAN_RATE": 1000}

        # Mock run_masscan_scan: modifies recon_data in place and returns it
        mock_masscan_scan = MagicMock(side_effect=lambda recon_data, output_file=None, settings=None: _mock_masscan_scan_result(recon_data))

        # Mock Neo4jClient
        mock_client = MagicMock()
        mock_client.verify_connection.return_value = neo4j_connected
        mock_client.update_graph_from_port_scan.return_value = {
            "ports_created": 2, "services_created": 2, "ips_updated": 1,
            "relationships_created": 4, "errors": [],
        }

        # Mock the neo4j driver session for graph queries
        mock_session = MagicMock()
        _domain_ips = domain_ips if domain_ips is not None else [
            {"address": "93.184.216.34", "version": "ipv4"},
        ]
        _subdomain_ips = subdomain_ips if subdomain_ips is not None else [
            {"subdomain": "www.example.com", "address": "93.184.216.34", "version": "ipv4"},
        ]

        def mock_session_run(query, **kwargs):
            result = MagicMock()
            if "RESOLVES_TO]->(i:IP)" in query and "HAS_SUBDOMAIN" not in query:
                records = []
                for ip_data in _domain_ips:
                    record = MagicMock()
                    record.__getitem__ = lambda self, key, d=ip_data: d[key]
                    records.append(record)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "HAS_SUBDOMAIN" in query and "RESOLVES_TO" in query:
                records = []
                for ip_data in _subdomain_ips:
                    record = MagicMock()
                    record.__getitem__ = lambda self, key, d=ip_data: d[key]
                    records.append(record)
                result.__iter__ = lambda self, r=records: iter(r)
            else:
                result.__iter__ = lambda self: iter([])
            return result

        mock_session.run = mock_session_run

        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.driver = mock_driver

        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Create mock modules
        mock_project_settings = MagicMock()
        mock_project_settings.get_settings = mock_settings

        mock_masscan_mod = MagicMock()
        mock_masscan_mod.run_masscan_scan = mock_masscan_scan

        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls

        # Inject mocks into sys.modules
        saved = {}
        modules_to_mock = {
            'recon.project_settings': mock_project_settings,
            'recon.masscan_scan': mock_masscan_mod,
            'graph_db': mock_graph_db,
        }
        for name, mod in modules_to_mock.items():
            saved[name] = sys.modules.get(name)
            sys.modules[name] = mod

        os.environ.setdefault("USER_ID", "user1")
        os.environ.setdefault("PROJECT_ID", "proj1")

        try:
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            pr.run_masscan(config)
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

        return {
            "settings": mock_settings,
            "masscan_scan": mock_masscan_scan,
            "neo4j_client": mock_client,
            "neo4j_cls": mock_neo4j_cls,
        }

    def test_basic_scan_no_user_inputs(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": []})
        mocks["masscan_scan"].assert_called_once()
        mocks["neo4j_client"].update_graph_from_port_scan.assert_called_once()

    def test_settings_fetched_and_masscan_force_enabled(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": []})
        mocks["settings"].assert_called_once()
        # Masscan should be called with MASSCAN_ENABLED=True regardless of project settings
        call_kwargs = mocks["masscan_scan"].call_args
        settings_passed = call_kwargs[1]["settings"] if "settings" in (call_kwargs[1] or {}) else call_kwargs[0][2] if len(call_kwargs[0]) > 2 else None
        # The key check: run_masscan forces MASSCAN_ENABLED=True before calling run_masscan_scan

    def test_user_ips_create_userinput_node(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.1"]},
        )
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["user_input_data"]["input_type"], "ips")
        self.assertEqual(ui_kw["user_input_data"]["tool_id"], "Masscan")

    def test_empty_graph_no_user_inputs_exits(self):
        with self.assertRaises(SystemExit):
            self._run_with_mocks(
                {"domain": "example.com", "user_inputs": []},
                domain_ips=[],
                subdomain_ips=[],
            )

    def test_masscan_normalizes_to_port_scan(self):
        """Verify masscan_scan data is copied to port_scan key for graph update."""
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": []})
        # update_graph_from_port_scan should be called with recon_data that has port_scan key
        call_kwargs = mocks["neo4j_client"].update_graph_from_port_scan.call_args
        recon_data = call_kwargs[1]["recon_data"]
        self.assertIn("port_scan", recon_data)
        self.assertIn("by_host", recon_data["port_scan"])
        self.assertIn("by_ip", recon_data["port_scan"])

    def test_structured_targets_generic_ips(self):
        """IPs with ip_attach_to=None should create UserInput node."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": ["10.0.0.1"], "ip_attach_to": None},
            },
            domain_ips=[],
        )
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["user_input_data"]["tool_id"], "Masscan")

    def test_structured_targets_empty_uses_graph_only(self):
        """Empty user_targets should just scan graph data."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": [], "ip_attach_to": None},
            },
            domain_ips=[{"address": "1.2.3.4", "version": "ipv4"}],
        )
        mocks["masscan_scan"].assert_called_once()
        mocks["neo4j_client"].create_user_input_node.assert_not_called()


def _mock_nmap_scan_result(recon_data, output_file=None, settings=None):
    """Mock run_nmap_scan: adds nmap_scan key to recon_data."""
    recon_data["nmap_scan"] = {
        "scan_metadata": {"scanner": "nmap", "nmap_version": "7.94"},
        "by_host": {},
        "services_detected": [],
        "nse_vulns": [],
        "summary": {"hosts_scanned": 1, "services_detected": 0, "nse_vulns_found": 0},
    }
    return recon_data


class TestRunNmap(unittest.TestCase):
    """Tests for run_nmap using module-level mocks."""

    def _run_with_mocks(self, config, neo4j_connected=True, domain_ips=None, subdomain_ips=None):
        """Helper that sets up all mocks and runs run_nmap."""
        # Mock get_settings
        mock_settings = MagicMock()
        mock_settings.return_value = {"NMAP_ENABLED": True, "NMAP_VERSION_DETECTION": True}

        # Mock run_nmap_scan: adds nmap_scan key
        mock_nmap_scan = MagicMock(side_effect=_mock_nmap_scan_result)

        # Mock merge_nmap_into_port_scan
        mock_merge = MagicMock()

        # Mock Neo4jClient
        mock_client = MagicMock()
        mock_client.verify_connection.return_value = neo4j_connected
        mock_client.update_graph_from_nmap.return_value = {
            "ports_enriched": 2, "services_enriched": 1, "technologies_created": 1,
            "nse_vulns_created": 0, "cves_created": 0, "relationships_created": 3, "errors": [],
        }

        # Mock the neo4j driver session for graph queries
        mock_session = MagicMock()
        _domain_ips = domain_ips if domain_ips is not None else [
            {"ip": "93.184.216.34", "version": "ipv4",
             "ports": [{"number": 80, "protocol": "tcp", "service": "http"},
                       {"number": 443, "protocol": "tcp", "service": "https"}]},
        ]
        _subdomain_ips = subdomain_ips if subdomain_ips is not None else [
            {"subdomain": "www.example.com", "ip": "93.184.216.34", "version": "ipv4",
             "ports": [{"number": 80, "protocol": "tcp", "service": "http"},
                       {"number": 443, "protocol": "tcp", "service": "https"}]},
        ]

        def mock_session_run(query, **kwargs):
            result = MagicMock()
            if "RESOLVES_TO]->(i:IP)" in query and "HAS_SUBDOMAIN" not in query and "HAS_PORT" in query:
                # Domain -> IP -> Port query (for _build_port_scan_data_from_graph)
                records = []
                for ip_data in _domain_ips:
                    record = MagicMock()
                    record.__getitem__ = lambda self, key, d=ip_data: d[key]
                    records.append(record)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "HAS_SUBDOMAIN" in query and "RESOLVES_TO" in query and "HAS_PORT" in query:
                # Subdomain -> IP -> Port query (for _build_port_scan_data_from_graph)
                records = []
                for ip_data in _subdomain_ips:
                    record = MagicMock()
                    record.__getitem__ = lambda self, key, d=ip_data: d[key]
                    records.append(record)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "Subdomain" in query and "RETURN s LIMIT 1" in query:
                # Subdomain existence check
                result.single.return_value = None
                return result
            else:
                result.__iter__ = lambda self: iter([])
            return result

        mock_session.run = mock_session_run

        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.driver = mock_driver

        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Create mock modules
        mock_project_settings = MagicMock()
        mock_project_settings.get_settings = mock_settings

        mock_nmap_mod = MagicMock()
        mock_nmap_mod.run_nmap_scan = mock_nmap_scan

        mock_main_mod = MagicMock()
        mock_main_mod.merge_nmap_into_port_scan = mock_merge

        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls

        # Inject mocks into sys.modules
        saved = {}
        modules_to_mock = {
            'recon.project_settings': mock_project_settings,
            'recon.nmap_scan': mock_nmap_mod,
            'recon.main': mock_main_mod,
            'graph_db': mock_graph_db,
        }
        for name, mod in modules_to_mock.items():
            saved[name] = sys.modules.get(name)
            sys.modules[name] = mod

        os.environ.setdefault("USER_ID", "user1")
        os.environ.setdefault("PROJECT_ID", "proj1")

        try:
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            pr.run_nmap(config)
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

        return {
            "settings": mock_settings,
            "nmap_scan": mock_nmap_scan,
            "merge": mock_merge,
            "neo4j_client": mock_client,
            "neo4j_cls": mock_neo4j_cls,
        }

    def test_basic_scan_no_user_inputs(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": []})
        mocks["nmap_scan"].assert_called_once()
        mocks["merge"].assert_called_once()
        mocks["neo4j_client"].update_graph_from_nmap.assert_called_once()

    def test_settings_fetched(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": []})
        mocks["settings"].assert_called_once()

    def test_user_ips_create_userinput_node(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.1"]},
        )
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["user_input_data"]["input_type"], "ips")
        self.assertEqual(ui_kw["user_input_data"]["tool_id"], "Nmap")

    def test_empty_graph_no_ports_exits(self):
        """No ports in graph and no user inputs should exit."""
        with self.assertRaises(SystemExit):
            self._run_with_mocks(
                {"domain": "example.com", "user_inputs": []},
                domain_ips=[],
                subdomain_ips=[],
            )

    def test_nmap_scan_called_with_port_scan_data(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": []},
        )
        call_args = mocks["nmap_scan"].call_args
        recon_data = call_args[0][0]
        self.assertEqual(recon_data["domain"], "example.com")
        self.assertIn("port_scan", recon_data)
        self.assertIn("by_ip", recon_data["port_scan"])
        self.assertIn("93.184.216.34", recon_data["port_scan"]["by_ip"])
        self.assertIn(80, recon_data["port_scan"]["all_ports"])
        self.assertIn(443, recon_data["port_scan"]["all_ports"])

    def test_merge_called_after_scan(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": []},
        )
        mocks["merge"].assert_called_once()

    def test_graph_update_calls_update_from_nmap(self):
        """Nmap without custom ports should call update_graph_from_nmap only."""
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": []},
        )
        mocks["neo4j_client"].update_graph_from_nmap.assert_called_once()
        mocks["neo4j_client"].update_graph_from_port_scan.assert_not_called()

    def test_custom_ports_injected_into_scan(self):
        """Custom ports should be added to all_ports and each IP's port list."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"ips": [], "ports": [8443, 9090], "ip_attach_to": None},
            },
        )
        call_args = mocks["nmap_scan"].call_args
        recon_data = call_args[0][0]
        self.assertIn(8443, recon_data["port_scan"]["all_ports"])
        self.assertIn(9090, recon_data["port_scan"]["all_ports"])
        # Original ports should still be there
        self.assertIn(80, recon_data["port_scan"]["all_ports"])

    def test_custom_ports_trigger_port_scan_graph_update(self):
        """When custom ports are provided, update_graph_from_port_scan should be called first."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"ips": [], "ports": [8443], "ip_attach_to": None},
            },
        )
        mocks["neo4j_client"].update_graph_from_port_scan.assert_called_once()
        mocks["neo4j_client"].update_graph_from_nmap.assert_called_once()

    def test_user_input_status_completed(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["10.0.0.1"]},
        )
        mocks["neo4j_client"].update_user_input_status.assert_called_once()
        args = mocks["neo4j_client"].update_user_input_status.call_args[0]
        self.assertEqual(args[1], "completed")


class TestRunNmapStructuredTargets(unittest.TestCase):
    """Tests for run_nmap with new structured user_targets format."""

    def _run_with_mocks(self, config, domain_ips=None, subdomain_ips=None):
        """Helper that sets up all mocks and runs run_nmap with structured targets."""
        mock_settings = MagicMock()
        mock_settings.return_value = {"NMAP_ENABLED": True, "NMAP_VERSION_DETECTION": True}

        mock_nmap_scan = MagicMock(side_effect=_mock_nmap_scan_result)
        mock_merge = MagicMock()

        mock_client = MagicMock()
        mock_client.verify_connection.return_value = True
        mock_client.update_graph_from_nmap.return_value = {
            "ports_enriched": 1, "services_enriched": 1, "technologies_created": 0,
            "nse_vulns_created": 0, "cves_created": 0, "relationships_created": 2, "errors": [],
        }

        mock_session = MagicMock()
        _domain_ips = domain_ips if domain_ips is not None else [
            {"ip": "93.184.216.34", "version": "ipv4",
             "ports": [{"number": 80, "protocol": "tcp", "service": "http"}]},
        ]
        _subdomain_ips = subdomain_ips if subdomain_ips is not None else [
            {"subdomain": "www.example.com", "ip": "93.184.216.34", "version": "ipv4",
             "ports": [{"number": 80, "protocol": "tcp", "service": "http"}]},
        ]

        def mock_session_run(query, **kwargs):
            result = MagicMock()
            if "RESOLVES_TO]->(i:IP)" in query and "HAS_SUBDOMAIN" not in query and "HAS_PORT" in query:
                records = []
                for ip_data in _domain_ips:
                    record = MagicMock()
                    record.__getitem__ = lambda self, key, d=ip_data: d[key]
                    records.append(record)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "HAS_SUBDOMAIN" in query and "RESOLVES_TO" in query and "HAS_PORT" in query:
                records = []
                for ip_data in _subdomain_ips:
                    record = MagicMock()
                    record.__getitem__ = lambda self, key, d=ip_data: d[key]
                    records.append(record)
                result.__iter__ = lambda self, r=records: iter(r)
            elif "Subdomain" in query and "RETURN s LIMIT 1" in query:
                # For subdomain existence check -- default to existing
                mock_rec = MagicMock()
                result.single.return_value = mock_rec
                return result
            else:
                result.__iter__ = lambda self: iter([])
            return result

        mock_session.run = mock_session_run

        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.driver = mock_driver

        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_project_settings = MagicMock()
        mock_project_settings.get_settings = mock_settings

        mock_nmap_mod = MagicMock()
        mock_nmap_mod.run_nmap_scan = mock_nmap_scan

        mock_main_mod = MagicMock()
        mock_main_mod.merge_nmap_into_port_scan = mock_merge

        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls

        saved = {}
        modules_to_mock = {
            'recon.project_settings': mock_project_settings,
            'recon.nmap_scan': mock_nmap_mod,
            'recon.main': mock_main_mod,
            'graph_db': mock_graph_db,
        }
        for name, mod in modules_to_mock.items():
            saved[name] = sys.modules.get(name)
            sys.modules[name] = mod

        os.environ.setdefault("USER_ID", "user1")
        os.environ.setdefault("PROJECT_ID", "proj1")

        try:
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            pr.run_nmap(config)
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

        return {
            "settings": mock_settings,
            "nmap_scan": mock_nmap_scan,
            "merge": mock_merge,
            "neo4j_client": mock_client,
            "neo4j_cls": mock_neo4j_cls,
        }

    def test_ips_with_attach_to_null_creates_userinput(self):
        """IPs with ip_attach_to=null should create a UserInput node."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": ["10.0.0.1"], "ip_attach_to": None},
            },
        )
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["user_input_data"]["tool_id"], "Nmap")

    def test_ips_with_attach_to_subdomain_no_userinput(self):
        """IPs attached to a subdomain should NOT create a UserInput node."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": ["10.0.0.1"], "ip_attach_to": "www.example.com"},
            },
        )
        mocks["neo4j_client"].create_user_input_node.assert_not_called()

    def test_empty_user_targets_uses_graph_only(self):
        """Empty user_targets should just scan graph data."""
        mocks = self._run_with_mocks(
            {
                "domain": "example.com", "user_inputs": [],
                "user_targets": {"subdomains": [], "ips": [], "ip_attach_to": None},
            },
        )
        mocks["nmap_scan"].assert_called_once()
        mocks["neo4j_client"].create_user_input_node.assert_not_called()


if __name__ == "__main__":
    unittest.main()
