import http.client
import os
import sys
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT / "src"), str(_ROOT / "install" / "macos")]

import router_admin_interface_bypass as addon
import service


class MacOSServiceTests(unittest.TestCase):
    def test_definition_uses_absolute_paths_and_user_scope(self):
        project = Path("/Users/example/Router Proxy")
        home = Path("/Users/example")
        python = project / ".venv/bin/python"
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(addon.DESTINATION_VARIABLE, None)
            os.environ.pop(addon.TARGET_VARIABLE, None)
            definition = service.service_definition(project, home, python)
        self.assertEqual(plistlib.loads(plistlib.dumps(definition)), definition)
        self.assertEqual(definition["ProgramArguments"][0], str(python))
        self.assertEqual(
            definition["ProgramArguments"][-1],
            str(project / "src" / "router_admin_interface_bypass.py"),
        )
        self.assertIn("127.0.0.1", definition["ProgramArguments"])
        self.assertIn("ssl_insecure=true", definition["ProgramArguments"])
        self.assertIn(f"confdir={home / '.mitmproxy'}", definition["ProgramArguments"])
        self.assertTrue(definition["KeepAlive"])
        self.assertTrue(definition["RunAtLoad"])
        self.assertNotIn("UserName", definition)
        self.assertEqual(definition["EnvironmentVariables"]["HOME"], str(home))
        self.assertEqual(
            definition["EnvironmentVariables"][addon.DESTINATION_VARIABLE], addon.ROUTER_HOST
        )
        self.assertEqual(definition["EnvironmentVariables"][addon.TARGET_VARIABLE], addon.ROUTER_IP)

    def test_definition_records_explicit_destination_and_target(self):
        project = Path("/Users/example/Router Proxy")
        home = Path("/Users/example")
        python = project / ".venv/bin/python"
        definition = service.service_definition(
            project, home, python, destination="gateway.example", target="10.1.1.1"
        )
        environment = definition["EnvironmentVariables"]
        self.assertEqual(environment[addon.DESTINATION_VARIABLE], "gateway.example")
        self.assertEqual(environment[addon.TARGET_VARIABLE], "10.1.1.1")

    def test_missing_job_is_distinct_from_launchctl_error(self):
        for code in (0, 113):
            with self.subTest(code=code), patch.object(
                service.subprocess, "run",
                return_value=subprocess.CompletedProcess([], code, "", "not loaded"),
            ):
                self.assertEqual(service.loaded_service("gui/502/test").returncode, code)
        with patch.object(
            service.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 1, "", "permission denied"),
        ):
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                service.loaded_service("gui/502/test")

    def test_readiness_requires_running_job_and_http_response(self):
        connection = Mock()
        connection.getresponse.return_value.status = 200
        with patch.object(service, "loaded_service", return_value=Mock(
            returncode=0, stdout="pid = 123",
        )), patch.object(
            service.http.client, "HTTPConnection", return_value=connection
        ):
            service.wait_until_ready("gui/502/test")
        connection.request.assert_called_once_with("GET", "http://mitm.it/")
        connection.close.assert_called_once()

    def test_readiness_reports_connection_failures_and_closes_connection(self):
        connection = Mock()
        connection.request.side_effect = http.client.RemoteDisconnected("closed")
        with patch.object(service, "loaded_service", return_value=Mock(
            returncode=0, stdout="pid = 123",
        )), patch.object(
            service.http.client, "HTTPConnection", return_value=connection
        ), patch.object(service.time, "monotonic", side_effect=[0, 0, 16]), patch.object(
            service.time, "sleep"
        ):
            with self.assertRaisesRegex(RuntimeError, "closed"):
                service.wait_until_ready("gui/502/test")
        connection.close.assert_called_once()

    def test_install_and_failed_start_cleanup(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as tmp:
                home = Path(tmp)
                project = home / "Router Proxy"
                python = project / ".venv/bin/python"
                python.parent.mkdir(parents=True)
                python.touch()
                plist = home / "Library/LaunchAgents" / f"{service.LABEL}.plist"
                with patch.object(service, "PROJECT", project), patch.object(
                    service.sys, "prefix", str(project / ".venv")
                ), patch.object(service, "loaded_service", side_effect=[
                    Mock(returncode=113), Mock(returncode=0)
                ]), patch.object(service.socket, "socket"), patch.object(
                    service.subprocess, "run"
                ) as run, patch.object(
                    service.trust_certs,
                    "trust_certificates",
                    return_value=service.trust_certs.TrustReport(),
                ) as trust, patch.object(
                    service, "wait_until_ready",
                    side_effect=RuntimeError("not ready") if failed else None,
                ):
                    if failed:
                        with self.assertRaisesRegex(RuntimeError, "not ready"):
                            service.install(plist, home, "gui/502", "gui/502/test")
                        self.assertFalse(plist.exists())
                        run.assert_any_call(
                            [service.LAUNCHCTL, "bootout", "gui/502/test"], check=True
                        )
                    else:
                        service.install(plist, home, "gui/502", "gui/502/test")
                        self.assertEqual(plist.stat().st_mode & 0o777, 0o600)
                        with plist.open("rb") as source:
                            self.assertEqual(plistlib.load(source)["Label"], service.LABEL)
                    trust.assert_called_once_with()
                    run.assert_any_call(
                        [service.LAUNCHCTL, "bootstrap", "gui/502", str(plist)],
                        check=True,
                    )

    def test_install_refuses_existing_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "existing.plist"
            plist.write_text("do not overwrite")
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                service.install(plist, Path(tmp), "gui/502", "gui/502/test")
            self.assertEqual(plist.read_text(), "do not overwrite")

    def test_install_refuses_root_owned_launch_agents(self):
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp) / "LaunchAgents"
            agents.mkdir()
            with patch.object(service.os, "access", return_value=False), patch.object(
                Path, "owner", return_value="root"
            ), patch.object(service.os, "getlogin", return_value="db0d"):
                with self.assertRaisesRegex(RuntimeError, "sudo chown db0d:staff"):
                    service.ensure_user_writable(agents)

    def test_uninstall_uses_current_user_and_preserves_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            plist = home / "Library/LaunchAgents" / f"{service.LABEL}.plist"
            plist.parent.mkdir(parents=True)
            plist.touch()
            retained = home / ".mitmproxy"
            retained.mkdir()
            with patch.object(service.sys, "argv", ["service", "uninstall"]), patch.object(
                service.sys, "platform", "darwin"
            ), patch.object(service.os, "getuid", return_value=502), patch.object(
                service.Path, "home", return_value=home
            ), patch.object(
                service, "loaded_service", return_value=Mock(returncode=0)
            ), patch.object(service.subprocess, "run") as run:
                self.assertEqual(service.main(), 0)
                run.assert_called_once_with(
                    [service.LAUNCHCTL, "bootout", f"gui/502/{service.LABEL}"],
                    check=True,
                )
            self.assertFalse(plist.exists())
            self.assertTrue(retained.exists())


if __name__ == "__main__":
    unittest.main()
