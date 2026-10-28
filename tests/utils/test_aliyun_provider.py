"""Credential mount protections; no API requests or certificate issuance."""

import sys
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from pydantic import ValidationError

JOBS_PATH = Path(__file__).resolve().parents[2] / "src/common/core/letsencrypt/jobs"
sys.path.insert(0, str(JOBS_PATH))
from letsencrypt_providers import AliyunProvider


class AliyunProviderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.mount = patch("letsencrypt_providers.ALIDNS_SECRETS_PATH", self.root)
        self.mount.start()
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.mount.stop)
        self.file = self.root / "acceptance.ini"
        self.content = b"dns_aliyun_next_access_key_id = fake-id\ndns_aliyun_next_access_key_secret = fake-secret\n"
        self.file.write_bytes(self.content)
        self.file.chmod(0o640)
        self.provider = AliyunProvider(credentials_reference="acceptance")

    def test_reference_resolves_without_serializing_keys(self):
        self.assertEqual(self.provider.get_credentials_path(), self.file)
        self.assertEqual(self.provider.get_formatted_credentials(), self.content)
        self.assertEqual(self.provider.model_dump(), {"credentials_reference": "acceptance"})
        self.assertEqual(self.provider.get_extra_args(), ["-a", "dns-aliyun-next"])
        self.assertNotIn("fake-secret", repr(self.provider))

    def test_reference_cannot_escape_mount(self):
        for reference in ("../acceptance", "/tmp/acceptance", "a/b", "", "a" * 65):
            with self.assertRaises(ValidationError):
                AliyunProvider(credentials_reference=reference)

    def test_symlink_is_not_followed(self):
        self.file.unlink()
        self.file.symlink_to(self.root / "elsewhere.ini")
        with self.assertRaises(OSError):
            self.provider.get_formatted_credentials()

    def test_world_readable_or_group_writable_file_is_rejected(self):
        for mode in (0o644, 0o660):
            self.file.chmod(mode)
            with self.assertRaises(ValueError):
                self.provider.get_formatted_credentials()

    def test_invalid_ini_reports_no_secret_values(self):
        for data in (b"dns_aliyun_next_access_key_id = fake-id\n", self.content + b"unexpected = fake-secret\n", self.content + b"[extra]\nkey=fake-secret\n"):
            self.file.write_bytes(data)
            with self.assertRaises(ValueError) as exc:
                self.provider.get_formatted_credentials()
            self.assertNotIn("fake-secret", str(exc.exception))

    def test_oversize_file_is_rejected(self):
        self.file.write_bytes(b"a" * 16385)
        with self.assertRaises(ValueError):
            self.provider.get_formatted_credentials()

    @unittest.skipUnless(sys.platform == "linux", "BunkerWeb common_utils uses Linux sched_getaffinity")
    def test_certbot_renewal_plugin_and_credential_aliases(self):
        sys.path.insert(0, str(JOBS_PATH.parents[2] / "utils"))
        from letsencrypt_utils import renewal_dns_provider

        self.assertEqual(
            renewal_dns_provider("authenticator = dns-aliyun-next\ndns_aliyun_next_credentials = /run/secrets/bunkerweb-alidns/acceptance.ini\n"),
            ("aliyun", Path("/run/secrets/bunkerweb-alidns/acceptance.ini")),
        )
        self.assertEqual(
            renewal_dns_provider("authenticator = dns-cloudflare\ndns_cloudflare_credentials = /tmp/cloudflare.ini\n"),
            ("cloudflare", Path("/tmp/cloudflare.ini")),
        )
        self.assertEqual(renewal_dns_provider("authenticator = manual\n"), ("manual", None))

    @unittest.skipUnless(sys.platform == "linux", "BunkerWeb common_utils uses Linux sched_getaffinity")
    def test_scheduler_extracts_global_and_multisite_reference(self):
        sys.path.insert(0, str(JOBS_PATH.parents[2] / "utils"))
        from letsencrypt_utils import extract_provider

        for prefix in ("", "example.com_"):
            with patch.dict(os.environ, {prefix + "LETS_ENCRYPT_DNS_CREDENTIAL_REFERENCE": "acceptance"}, clear=True):
                provider = extract_provider("example.com", prefix + "LETS_ENCRYPT_DNS_CREDENTIAL_ITEM", "aliyun")
                self.assertEqual(provider.get_credentials_path(), self.file)
                self.assertEqual(provider.model_dump(), {"credentials_reference": "acceptance"})

    @unittest.skipUnless(sys.platform == "linux", "BunkerWeb common_utils uses Linux sched_getaffinity")
    def test_scheduler_rejects_missing_reference_without_logging_keys(self):
        sys.path.insert(0, str(JOBS_PATH.parents[2] / "utils"))
        from letsencrypt_utils import extract_provider

        logger = Mock()
        with patch.dict(os.environ, {"LETS_ENCRYPT_DNS_CREDENTIAL_ITEM": "access_key_secret fake-secret"}, clear=True):
            self.assertIsNone(extract_provider("example.com", "LETS_ENCRYPT_DNS_CREDENTIAL_ITEM", "aliyun", logger=logger))
        self.assertNotIn("fake-secret", str(logger.mock_calls))


if __name__ == "__main__":
    unittest.main()
