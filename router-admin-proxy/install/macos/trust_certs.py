"""Install public certificates from the project's certs directory.

CA certificates are added to the login keychain and trusted for SSL. Leaf
certificates are imported into the login keychain, but recent macOS releases
reject CLI trust settings for non-CA certificates. Private keys are refused.

Run from the project directory:

    uv run --frozen python install/macos/trust_certs.py
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import os
from pathlib import Path
import subprocess
import sys

from cryptography import x509

PROJECT = Path(__file__).resolve().parents[2]
CERTS = PROJECT / "certs"
SECURITY = "/usr/bin/security"
_CERTIFICATE_SUFFIXES = {".pem", ".crt", ".cer"}
_ALREADY_PRESENT = (
    "already exists in the keychain",
    "already in ",
    "CSSMERR_DL_CERT_ALREADY_EXISTS",
)


class CertificateError(ValueError):
    """A file in the certs directory cannot be installed."""


@dataclass
class TrustReport:
    """Result of installing the certs directory into the login keychain."""

    trusted: list[Path] = field(default_factory=list)
    imported: list[Path] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.trusted or self.imported)


def login_keychain(home: Path | None = None) -> Path:
    """Return the current user's login keychain."""
    root = Path.home() if home is None else home
    modern = root / "Library" / "Keychains" / "login.keychain-db"
    legacy = root / "Library" / "Keychains" / "login.keychain"
    if modern.exists() or not legacy.exists():
        return modern
    return legacy


def certificate_paths(certs_dir: Path | None = None) -> list[Path]:
    """Return the single-certificate files in the certs directory, in name order."""
    directory = CERTS if certs_dir is None else certs_dir
    if not directory.is_dir():
        return []
    paths = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.suffix.lower() not in _CERTIFICATE_SUFFIXES:
            continue
        data = path.read_bytes()
        if b"PRIVATE KEY" in data:
            raise CertificateError(f"{path.name} contains a private key and will not be installed")
        if data.count(b"BEGIN CERTIFICATE") != 1:
            raise CertificateError(f"{path.name} must contain exactly one certificate")
        paths.append(path)
    return paths


def is_certificate_authority(certificate: x509.Certificate) -> bool:
    """Return True when the certificate is a CA that macOS can trust via CLI."""
    try:
        return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def trust_certificates(
    certs_dir: Path | None = None,
    keychain: Path | None = None,
) -> TrustReport:
    """Install every public certificate. Trust CA certificates for SSL."""
    keychain = login_keychain() if keychain is None else keychain
    report = TrustReport()
    for path in certificate_paths(certs_dir):
        try:
            certificate = x509.load_pem_x509_certificate(path.read_bytes())
        except ValueError as error:
            raise CertificateError(f"{path.name}: invalid PEM certificate: {error}") from error
        if is_certificate_authority(certificate):
            _run_security(
                [
                    SECURITY,
                    "add-trusted-cert",
                    "-r",
                    "trustRoot",
                    "-p",
                    "ssl",
                    "-k",
                    str(keychain),
                    str(path),
                ],
                path,
            )
            report.trusted.append(path)
            continue
        _import_certificate(path, keychain)
        report.imported.append(path)
    return report


def describe_report(report: TrustReport, certs_dir: Path | None = None) -> list[str]:
    """Return human-readable lines for an install report."""
    directory = CERTS if certs_dir is None else certs_dir
    if not report:
        return [f"No certificates found in {directory}"]
    lines = []
    if report.trusted:
        names = ", ".join(path.name for path in report.trusted)
        lines.append(f"Trusted for SSL in the login keychain: {names}")
    if report.imported:
        names = ", ".join(path.name for path in report.imported)
        lines.append(
            "Imported into the login keychain without SSL trust settings: "
            f"{names}. Recent macOS releases only allow CLI trust for CA "
            "certificates. Put a CA such as ~/.mitmproxy/mitmproxy-ca-cert.pem "
            "in certs/, or open Keychain Access and set Secure Sockets Layer "
            "to Always Trust for these leaf certificates."
        )
    return lines


def _import_certificate(path: Path, keychain: Path) -> None:
    _run_security([SECURITY, "add-certificates", "-k", str(keychain), str(path)], path)


def _run_security(command: list[str], path: Path) -> None:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        return
    detail = (result.stderr or result.stdout).strip() or f"exit status {result.returncode}"
    if any(marker in detail for marker in _ALREADY_PRESENT):
        return
    raise CertificateError(f"{path.name}: {detail}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if sys.platform != "darwin" or os.getuid() == 0:
        parser.error("Run as your normal logged-in macOS user, without sudo.")
    try:
        report = trust_certificates()
    except (OSError, CertificateError) as error:
        print(f"Certificate trust error: {error}", file=sys.stderr)
        return 1
    for line in describe_report(report):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
