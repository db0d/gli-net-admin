import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mitmproxy import http, options, tls
from mitmproxy.proxy import context
from mitmproxy.test import tflow

import router_admin_interface_bypass as addon


class RouterAdminTests(unittest.TestCase):
    def setUp(self):
        self._environment = patch.dict(os.environ, {}, clear=False)
        self._environment.start()
        os.environ.pop(addon.DESTINATION_VARIABLE, None)
        os.environ.pop(addon.TARGET_VARIABLE, None)
        self.addCleanup(self._environment.stop)

    def client_hello(self, sni, destination):
        flow = tflow.tflow()
        ctx = context.Context(flow.client_conn, options.Options())
        ctx.server.address = destination
        return tls.ClientHelloData(ctx, Mock(spec=tls.ClientHello, sni=sni))

    def test_router_is_intercepted_without_sni(self):
        for destination in (addon.ROUTER_HOST, addon.ROUTER_IP):
            with self.subTest(destination=destination):
                data = self.client_hello(None, (destination, 443))
                addon.tls_clienthello(data)
                self.assertFalse(data.ignore_connection)

    def test_router_destination_is_intercepted_regardless_of_sni(self):
        for destination in ("ROUTER.DBOD.LOCAL.", addon.ROUTER_IP):
            for sni in (None, addon.ROUTER_HOST, "example.com"):
                with self.subTest(destination=destination, sni=sni):
                    data = self.client_hello(sni, (destination, 443))
                    addon.tls_clienthello(data)
                    self.assertFalse(data.ignore_connection)

    def test_unrelated_tls_passes_through(self):
        for destination in (
            "example.com",
            "mitm.it",
            "router.dbod.local.example.com",
            "192.168.8.10",
        ):
            for sni in (None, "example.com", addon.ROUTER_HOST, addon.ROUTER_IP):
                with self.subTest(destination=destination, sni=sni):
                    data = self.client_hello(sni, (destination, 443))
                    addon.tls_clienthello(data)
                    self.assertTrue(data.ignore_connection)

    def test_unknown_destination_is_not_intercepted(self):
        for sni in (None, addon.ROUTER_HOST):
            with self.subTest(sni=sni):
                data = self.client_hello(sni, None)
                addon.tls_clienthello(data)
                self.assertTrue(data.ignore_connection)

    def test_existing_passthrough_decision_is_preserved(self):
        data = self.client_hello(None, (addon.ROUTER_HOST, 443))
        data.ignore_connection = True
        addon.tls_clienthello(data)
        self.assertTrue(data.ignore_connection)

    def test_rewrites_http_host_and_http2_authority(self):
        for version in ("HTTP/1.1", "HTTP/2.0"):
            for scheme, port, expected in (
                ("https", 443, addon.ROUTER_IP),
                ("https", 8443, f"{addon.ROUTER_IP}:8443"),
                ("http", 80, addon.ROUTER_IP),
                ("http", 8080, f"{addon.ROUTER_IP}:8080"),
            ):
                with self.subTest(version=version, scheme=scheme, port=port):
                    flow = tflow.tflow()
                    flow.request = http.Request.make(
                        "POST",
                        f"{scheme}://{addon.ROUTER_HOST}:{port}/admin?view=status",
                        b"payload",
                        {"Host": addon.ROUTER_HOST},
                    )
                    flow.request.http_version = version
                    if version == "HTTP/2.0":
                        flow.request.authority = addon.ROUTER_HOST
                    addon.request(flow)
                    self.assertEqual(flow.request.host, addon.ROUTER_IP)
                    self.assertEqual(flow.request.host_header, expected)
                    self.assertEqual(flow.request.headers["Host"], expected)
                    if version == "HTTP/2.0":
                        self.assertEqual(flow.request.authority, expected)
                    self.assertEqual(flow.request.port, port)
                    self.assertEqual(flow.request.scheme, scheme)
                    self.assertEqual(flow.request.path, "/admin?view=status")
                    self.assertEqual(flow.request.method, "POST")
                    self.assertEqual(flow.request.content, b"payload")

    def test_missing_host_header_is_created(self):
        flow = tflow.tflow()
        flow.request = http.Request.make("GET", f"https://{addon.ROUTER_HOST}/")
        flow.request.headers.pop("Host", None)
        addon.request(flow)
        self.assertEqual(flow.request.host_header, addon.ROUTER_IP)

    def test_non_alias_requests_are_unchanged(self):
        for hostname in ("example.com", "mitm.it", addon.ROUTER_IP):
            with self.subTest(hostname=hostname):
                flow = tflow.tflow()
                flow.request = http.Request.make(
                    "POST",
                    f"https://{hostname}:8443/path?query=value",
                    b"payload",
                    {"Host": f"{hostname}:8443", "X-Test": "unchanged"},
                )
                before = flow.request.get_state()
                addon.request(flow)
                self.assertEqual(flow.request.get_state(), before)

    def test_hostname_matching_is_exact_and_case_insensitive(self):
        for hostname, expected in (
            ("ROUTER.DBOD.LOCAL.", addon.ROUTER_IP),
            ("router.dbod.local.example.com", "router.dbod.local.example.com"),
            ("example.com", "example.com"),
        ):
            with self.subTest(hostname=hostname):
                flow = tflow.tflow()
                flow.request = http.Request.make(
                    "GET", f"https://{hostname}/", headers={"Host": hostname}
                )
                addon.request(flow)
                self.assertEqual(flow.request.host, expected)
                self.assertEqual(flow.request.host_header, expected)

    def test_environment_selects_the_destination_and_target(self):
        with patch.dict(
            os.environ,
            {addon.DESTINATION_VARIABLE: "Gateway.Example.", addon.TARGET_VARIABLE: "10.1.1.1"},
        ):
            intercepted = self.client_hello("example.com", ("gateway.example", 443))
            addon.tls_clienthello(intercepted)
            self.assertFalse(intercepted.ignore_connection)

            default_name = self.client_hello(None, (addon.ROUTER_HOST, 443))
            addon.tls_clienthello(default_name)
            self.assertTrue(default_name.ignore_connection)

            flow = tflow.tflow()
            flow.request = http.Request.make(
                "GET",
                "https://gateway.example:8443/admin",
                headers={"Host": "gateway.example:8443"},
            )
            addon.request(flow)
            self.assertEqual(flow.request.host, "10.1.1.1")
            self.assertEqual(flow.request.host_header, "10.1.1.1:8443")
            self.assertEqual(flow.request.path, "/admin")

    def test_override_rejects_a_url_or_port(self):
        for value in ("https://router.example", "router.example:443", "router.example/admin", ""):
            with self.subTest(value=value), patch.dict(
                os.environ, {addon.DESTINATION_VARIABLE: value}
            ):
                with self.assertRaises(addon.ConfigError):
                    addon.router_destination()


if __name__ == "__main__":
    unittest.main()
