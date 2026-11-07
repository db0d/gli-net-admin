import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "install" / "macos"))

import trust_certs


class TrustCertificateTests(unittest.TestCase):
    def test_trusts_ca_and_imports_leaf_without_trust_as_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            certs.mkdir()
            keychain = Path(tmp) / "login.keychain-db"
            _write_certificate(certs / "ca.pem", "Local CA", ca=True)
            _write_certificate(certs / "router.pem", "router.example", ca=False)
            (certs / "notes.txt").write_text("ignored")
            with patch.object(
                trust_certs.subprocess,
                "run",
                return_value=Mock(returncode=0, stdout="", stderr=""),
            ) as run:
                report = trust_certs.trust_certificates(certs, keychain)

            self.assertEqual([path.name for path in report.trusted], ["ca.pem"])
            self.assertEqual([path.name for path in report.imported], ["router.pem"])
            commands = {Path(call.args[0][-1]).name: call.args[0] for call in run.call_args_list}
            self.assertEqual(
                commands["ca.pem"],
                [
                    trust_certs.SECURITY,
                    "add-trusted-cert",
                    "-r",
                    "trustRoot",
                    "-p",
                    "ssl",
                    "-k",
                    str(keychain),
                    str(certs / "ca.pem"),
                ],
            )
            self.assertEqual(
                commands["router.pem"],
                [
                    trust_certs.SECURITY,
                    "add-certificates",
                    "-k",
                    str(keychain),
                    str(certs / "router.pem"),
                ],
            )
            self.assertNotIn("trustAsRoot", " ".join(" ".join(call.args[0]) for call in run.call_args_list))

    def test_already_present_certificates_are_treated_as_success(self):
        messages = (
            "SecCertificateAddToKeychain: The specified item already exists in the keychain.",
            "security: /tmp/router.pem: already in /Users/example/Library/Keychains/login.keychain-db",
        )
        for message in messages:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmp:
                certs = Path(tmp)
                keychain = Path(tmp) / "login.keychain-db"
                _write_certificate(certs / "router.pem", "router.example", ca=False)
                with patch.object(
                    trust_certs.subprocess,
                    "run",
                    return_value=Mock(returncode=1, stdout="", stderr=message),
                ):
                    report = trust_certs.trust_certificates(certs, keychain)
                self.assertEqual([path.name for path in report.imported], ["router.pem"])

    def test_private_key_is_refused_before_any_certificate_is_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp)
            _write_certificate(certs / "router.pem", "router.example", ca=False)
            (certs / "secret.pem").write_text("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n")
            with patch.object(trust_certs.subprocess, "run") as run:
                with self.assertRaisesRegex(trust_certs.CertificateError, "secret.pem"):
                    trust_certs.trust_certificates(certs, Path(tmp) / "login.keychain-db")
            run.assert_not_called()

    def test_empty_directory_trusts_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(trust_certs.subprocess, "run") as run:
                report = trust_certs.trust_certificates(Path(tmp), Path(tmp) / "login.keychain-db")
            self.assertFalse(report)
            run.assert_not_called()

    def test_describe_report_explains_leaf_import(self):
        report = trust_certs.TrustReport(
            trusted=[Path("ca.pem")],
            imported=[Path("router.pem")],
        )
        lines = trust_certs.describe_report(report)
        self.assertTrue(any("Trusted for SSL" in line and "ca.pem" in line for line in lines))
        self.assertTrue(any("without SSL trust settings" in line and "router.pem" in line for line in lines))


def _write_certificate(path: Path, common_name: str, ca: bool) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    unittest.main()
