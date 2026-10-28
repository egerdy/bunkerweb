"""Real OpenSSL certificate/key checks for native Certbot and custom layouts."""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


def load_guard():
    source = Path(os.environ["LKG_GUARD_SOURCE"]) if "LKG_GUARD_SOURCE" in os.environ else Path(__file__).resolve().parents[2] / "misc/fork/lkg/guard.py"
    spec = importlib.util.spec_from_file_location("fork_lkg_guard", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def issue(directory):
    directory.mkdir(parents=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=lkg-test.invalid",
            "-keyout",
            str(directory / "key.pem"),
            "-out",
            str(directory / "cert.pem"),
        ],
        check=True,
        capture_output=True,
    )


def certbot_layout(root):
    archive = root / "letsencrypt/etc/archive/test.invalid"
    issue(archive)
    (archive / "key.pem").rename(archive / "privkey1.pem")
    (archive / "cert.pem").rename(archive / "cert1.pem")
    (archive / "fullchain1.pem").write_bytes((archive / "cert1.pem").read_bytes())
    live = root / "letsencrypt/etc/live/test.invalid"
    live.mkdir(parents=True)
    for name in ("cert", "fullchain", "privkey"):
        (live / (name + ".pem")).symlink_to(archive / (name + "1.pem"))
    return live


class CertificatePreflightTest(unittest.TestCase):
    def setUp(self):
        self.guard = load_guard()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.cache = Path(directory.name)

    def test_native_certbot_live_symlinks(self):
        certbot_layout(self.cache)
        self.guard.check_certificates(self.cache)

    def test_custom_certificate_layout(self):
        issue(self.cache / "customcert/test.invalid")
        self.guard.check_certificates(self.cache)

    def test_certbot_wrong_private_key_is_rejected(self):
        live = certbot_layout(self.cache)
        issue(self.cache / "other")
        (live / "privkey.pem").unlink()
        (live / "privkey.pem").write_bytes((self.cache / "other/key.pem").read_bytes())
        with self.assertRaisesRegex(RuntimeError, "certificate/key pair preflight failed"):
            self.guard.check_certificates(self.cache)

    def test_certbot_missing_private_key_is_rejected(self):
        live = certbot_layout(self.cache)
        (live / "privkey.pem").unlink()
        with self.assertRaisesRegex(RuntimeError, "certificate/key pair preflight failed"):
            self.guard.check_certificates(self.cache)
