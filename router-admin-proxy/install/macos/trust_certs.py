"""Trust public certificates from the project's certs directory.

Installs each PEM certificate into the current user's login keychain and
marks it trusted for SSL. A CA certificate is trusted as a root. Any other
certificate is trusted only as itself. Private keys are refused.

Run from the project directory:

    uv run --frozen python install/macos/trust_certs.py
"""

import argparse
import os
from pathlib import Path
import subprocess
import sys

from cryptography import x509

PROJECT = Path(__file__).resolve().parents[2]
CERTS = PROJECT / "certs"
SECURITY = "/usr/bin/security"
_CERTIFICATE_SUFFIXES = {".pem", ".crt", ".cer"}


class CertificateError(ValueError):
    """A file in the certs directory cannot be trusted."""


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
            raise CertificateError(f"{path.name} contains a private key and will not be trusted")
        if data.count(b"BEGIN CERTIFICATE") != 1:
            raise CertificateError(f"{path.name} must contain exactly one certificate")
        paths.append(path)
    return paths


def trust_result(certificate: x509.Certificate) -> str:
    """Choose the Security framework trust result for one certificate."""
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return "trustAsRoot"
    return "trustRoot" if constraints.ca else "trustAsRoot"


def trust_certificates(
    certs_dir: Path | None = None,
    keychain: Path | None = None,
) -> list[Path]:
    """Trust every public certificate in the directory. Return the files trusted."""
    keychain = login_keychain() if keychain is None else keychain
    trusted = []
    for path in certificate_paths(certs_dir):
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
        subprocess.run(
            [
                SECURITY,
                "add-trusted-cert",
                "-r",
                trust_result(certificate),
                "-p",
                "ssl",
                "-k",
                str(keychain),
                str(path),
            ],
            check=True,
        )
        trusted.append(path)
    return trusted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if sys.platform != "darwin" or os.getuid() == 0:
        parser.error("Run as your normal logged-in macOS user, without sudo.")
    try:
        trusted = trust_certificates()
    except (OSError, CertificateError, subprocess.CalledProcessError) as error:
        print(f"Certificate trust error: {error}", file=sys.stderr)
        return 1
    if not trusted:
        print(f"No certificates found in {CERTS}")
        return 0
    for path in trusted:
        print(f"Trusted {path.name} for SSL in the login keychain")
    return 0


if __name__ == "__main__":
    sys.exit(main())
