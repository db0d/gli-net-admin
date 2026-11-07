"""Install or remove this project's per-user macOS LaunchAgent.

Installation also trusts the public certificates in the project certs directory.
"""

import argparse
import http.client
import os
from pathlib import Path
import plistlib
import socket
import subprocess
import sys
import time

_HERE = Path(__file__).resolve().parent
_SRC = _HERE.parents[1] / "src"
for _path in (_HERE, _SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import router_admin_interface_bypass as addon
import trust_certs

LABEL = "local.router-admin-proxy"
PROJECT = _HERE.parents[1]
LAUNCHCTL = "/bin/launchctl"


def service_definition(
    project: Path,
    home: Path,
    python: Path,
    destination: str | None = None,
    target: str | None = None,
) -> dict:
    logs = home / "Library" / "Logs" / LABEL
    return {
        "Label": LABEL,
        "ProgramArguments": [
            str(python),
            "-c",
            "from mitmproxy.tools.main import mitmdump; mitmdump()",
            "--mode", "regular",
            "--listen-host", "127.0.0.1",
            "--listen-port", "8080",
            "--set", "connection_strategy=lazy",
            "--set", "ssl_insecure=true",
            "--set", f"confdir={home / '.mitmproxy'}",
            "-s", str(project / "src" / "router_admin_interface_bypass.py"),
        ],
        "WorkingDirectory": str(project),
        "EnvironmentVariables": {
            "HOME": str(home),
            "PYTHONUNBUFFERED": "1",
            addon.DESTINATION_VARIABLE: destination if destination is not None else addon.router_destination(),
            addon.TARGET_VARIABLE: target if target is not None else addon.router_target(),
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "Umask": 0o077,
        "StandardOutPath": str(logs / "stdout.log"),
        "StandardErrorPath": str(logs / "stderr.log"),
    }


def loaded_service(target: str) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [LAUNCHCTL, "print", target], capture_output=True, text=True
    )
    # launchctl uses ESRCH (113 on macOS) when this job is not loaded.
    if result.returncode not in (0, 113):
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result


def wait_until_ready(target: str) -> None:
    deadline = time.monotonic() + 15
    last_error = "LaunchAgent has not started"
    while time.monotonic() < deadline:
        state = loaded_service(target)
        if state.returncode == 0 and "pid = " in state.stdout:
            connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=1)
            try:
                connection.request("GET", "http://mitm.it/")
                response = connection.getresponse()
                if response.status == 200:
                    return
                last_error = f"Proxy returned HTTP {response.status}"
            except (OSError, http.client.HTTPException) as error:
                last_error = str(error)
            finally:
                connection.close()
        else:
            last_error = state.stdout.strip() or state.stderr.strip()
        time.sleep(0.25)
    raise RuntimeError(f"Service did not become ready: {last_error}")


def ensure_user_writable(path: Path) -> None:
    """Require that this user can create files under the LaunchAgents directory."""
    directory = path if path.is_dir() else path.parent
    if not directory.exists():
        return
    if os.access(directory, os.W_OK | os.X_OK):
        return
    owner = directory.owner()
    raise RuntimeError(
        f"{directory} is not writable by this user (owner: {owner}). "
        "Do not use sudo with this installer. Fix ownership, then retry:\n"
        f"  sudo chown {os.getlogin()}:staff {directory}"
    )


def install(plist: Path, home: Path, domain: str, target: str) -> None:
    if plist.exists() or loaded_service(target).returncode == 0:
        raise RuntimeError("Service already exists. Uninstall it before reinstalling.")
    python = PROJECT / ".venv" / "bin" / "python"
    if Path(sys.prefix).absolute() != (PROJECT / ".venv").absolute():
        raise RuntimeError("Run with: uv run --frozen python install/macos/service.py install")
    if not python.is_file():
        raise RuntimeError("Project environment is missing. Run uv sync --frozen.")
    ensure_user_writable(plist.parent)
    # Refuse to compete with an existing interactive proxy or another service.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 8080))
    report = trust_certs.trust_certificates()
    definition = service_definition(PROJECT, home, python)
    plist.parent.mkdir(parents=True, exist_ok=True)
    (home / "Library" / "Logs" / LABEL).mkdir(parents=True, exist_ok=True, mode=0o700)
    with plist.open("xb") as output:
        os.chmod(plist, 0o600)
        plistlib.dump(definition, output)
    try:
        subprocess.run([LAUNCHCTL, "bootstrap", domain, str(plist)], check=True)
        wait_until_ready(target)
    except (OSError, RuntimeError, subprocess.CalledProcessError):
        if loaded_service(target).returncode == 0:
            subprocess.run([LAUNCHCTL, "bootout", target], check=True)
        plist.unlink()
        raise
    for line in trust_certs.describe_report(report):
        print(line)
    print(f"Installed and responsive at 127.0.0.1:8080: {plist}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "status", "uninstall"))
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This installer only supports macOS.")
    if os.getuid() == 0:
        parser.error(
            "Do not use sudo. This is a per-user LaunchAgent and must run as your "
            "normal logged-in macOS user. If ~/Library/LaunchAgents is root-owned, "
            "fix it first with: sudo chown \"$(whoami)\":staff ~/Library/LaunchAgents"
        )
    home = Path.home()
    plist = home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    domain = f"gui/{os.getuid()}"
    target = f"{domain}/{LABEL}"
    try:
        if args.action == "install":
            install(plist, home, domain, target)
        elif args.action == "status":
            state = loaded_service(target)
            if state.returncode != 0:
                print(f"Service is not loaded. Installed plist: {plist.exists()}")
                return 1
            print(state.stdout)
            wait_until_ready(target)
            print("Proxy is responding at 127.0.0.1:8080.")
        else:
            if loaded_service(target).returncode == 0:
                subprocess.run([LAUNCHCTL, "bootout", target], check=True)
            plist.unlink(missing_ok=True)
            print(
                "Service removed. Logs, trusted certificates, project, and network settings retained."
            )
    except trust_certs.CertificateError as error:
        print(f"Certificate install error: {error}", file=sys.stderr)
        print(
            "The LaunchAgent was not installed. Fix the certificates in certs/ "
            "or run: uv run --frozen python install/macos/trust_certs.py",
            file=sys.stderr,
        )
        return 1
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Service error: {error}", file=sys.stderr)
        if plist.exists() or loaded_service(target).returncode == 0:
            print(f"Check logs in {home / 'Library' / 'Logs' / LABEL}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
