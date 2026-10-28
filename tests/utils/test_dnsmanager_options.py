"""Account options must affect SDK transport, defaults and read-only checks."""

import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

import test_dnsmanager as fixtures
from alidns import AliDNSError
from bw_dnsmanager.providers import validate_credentials, validate_options
from bw_dnsmanager.resolution import check_record, canonical


class OptionTests(unittest.TestCase):
    def setUp(self):
        f = fixtures.StoreTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.save()
        self.f = f

    def test_options_persist_without_rotating_keys_and_configure_sdk(self):
        f = self.f
        with f.store.connect() as db:
            encrypted = db.execute("SELECT credentials FROM accounts").fetchone()[0]
        f.store.save_account(
            f.account_id,
            "Configured",
            ["example.com"],
            None,
            1,
            "admin",
            str(uuid4()),
            "alidns",
            {"http_timeout": 17, "region_id": "cn-shanghai", "ttl": 120, "line": "telecom", "propagation_timeout": 120},
        )
        profile = f.store.accounts(masked=True)[0]
        self.assertEqual(profile["options"]["ttl"], 120)
        client = f.store.account(f.account_id)
        self.assertEqual(client._runtime.read_timeout, 17000)
        self.assertEqual(client._runtime.connect_timeout, 17000)
        self.assertEqual(client._sdk._region_id, "cn-shanghai")
        with f.store.connect() as db:
            self.assertEqual(encrypted, db.execute("SELECT credentials FROM accounts").fetchone()[0])
        self.assertEqual(f.store.audit()[0]["intent"]["after"]["options"]["http_timeout"], 17)

    def test_legacy_options_defaults_and_preservation(self):
        f = self.f
        self.assertEqual(f.store.accounts()[0]["options"]["http_timeout"], 10)
        f.store.save_account(f.account_id, "Configured", ["example.com"], None, 1, "admin", str(uuid4()), "alidns", {"ttl": 120})
        f.store.save_account(f.account_id, "Renamed", ["example.com"], None, 2, "admin", str(uuid4()))
        self.assertEqual(f.store.accounts()[0]["options"]["ttl"], 120)

    def test_invalid_options_are_atomic(self):
        f = self.f
        for values in [
            {"http_timeout": 0},
            {"http_timeout": True},
            {"region_id": "https://other"},
            {"ttl": 0},
            {"polling_interval": 0},
            {"endpoint": "other"},
            {"auth_mode": "default"},
            {"propagation_timeout": 601},
        ]:
            with self.assertRaises(AliDNSError):
                f.store.save_account(f.account_id, "Invalid", ["example.com"], None, 1, "admin", str(uuid4()), "alidns", values)
        self.assertEqual(f.store.accounts()[0]["revision"], 1)
        self.assertEqual(len(f.store.audit()), 1)

    def test_auth_mode_change_requires_matching_credentials(self):
        f = self.f
        with self.assertRaisesRegex(AliDNSError, "InvalidCredentials"):
            f.store.save_account(f.account_id, "Role", ["example.com"], None, 1, "admin", str(uuid4()), "alidns", {"auth_mode": "ecs_ram_role"})
        with patch("bw_dnsmanager.configured_alidns.CredentialClient") as factory, patch("bw_dnsmanager.configured_alidns.SDKClient"):
            f.store.save_account(
                f.account_id, "Role", ["example.com"], {"ram_role": "test-role"}, 1, "admin", str(uuid4()), "alidns", {"auth_mode": "ecs_ram_role"}
            )
            f.store.account(f.account_id)
            config = factory.call_args.args[0]
            self.assertEqual(config.type, "ecs_ram_role")
            self.assertEqual(config.role_name, "test-role")
            self.assertTrue(config.disable_imds_v1)
        with self.assertRaises(AliDNSError):
            validate_credentials("alidns", {"access_key_id": "id", "access_key_secret": "secret", "ram_role": "role"})

    def test_options_removed_with_account(self):
        f = self.f
        f.store.delete_account(f.account_id, 1, "admin", str(uuid4()))
        with f.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM account_options").fetchone()[0], 0)


class ResolutionTests(unittest.TestCase):
    def test_resolver_matches_only_requested_name_and_type(self):
        client = Mock(options=validate_options("alidns", {"http_timeout": 13}))
        client.get_record.return_value = {"RecordId": "123", "RR": "www", "Type": "A", "Value": "192.0.2.10", "Status": "ENABLE"}
        response = Mock(status_code=200, content=b"response")
        response.json.return_value = {"Status": 0, "Answer": [{"name": "www.example.com.", "type": 1, "data": "192.0.2.10"}]}
        with patch("bw_dnsmanager.resolution.requests.Session") as session:
            session.return_value.__enter__.return_value.get.return_value = response
            result = check_record(client, "example.com", "123", 4)
            self.assertTrue(result["matched"])
            kwargs = session.return_value.__enter__.return_value.get.call_args.kwargs
            self.assertEqual(kwargs["timeout"], (2, 2))
            self.assertFalse(kwargs["allow_redirects"])
            response.json.return_value["Answer"][0]["name"] = "other.example.com."
            self.assertFalse(check_record(client, "example.com", "123")["matched"])

    def test_resolution_does_not_claim_global_success_or_unsupported_types(self):
        client = Mock(options=validate_options("alidns"))
        client.get_record.return_value = {"RecordId": "123", "RR": "*", "Type": "A"}
        with self.assertRaisesRegex(AliDNSError, "UnsupportedResolutionTest"):
            check_record(client, "example.com", "123")

    def test_txt_chunks_and_cname_normalization(self):
        self.assertEqual(canonical("TXT", '"hello " "world"'), "hello world")
        self.assertEqual(canonical("CNAME", "Target.Example.COM."), "target.example.com")

    def test_http_options_and_add_defaults(self):
        fixtures.HTTPTests.setUpClass()
        f = fixtures.HTTPTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        token = f.csrf()
        response = f.client.post(
            "/dnsmanager/accounts/save",
            json={
                "id": f.account_id,
                "label": "Options",
                "domains": ["example.com"],
                "credentials": None,
                "revision": 1,
                "operation_id": str(uuid4()),
                "options": {"ttl": 120, "line": "telecom", "propagation_timeout": 120},
            },
            headers={"X-Test-User": "admin", "X-CSRFToken": token},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(f.write().status_code, 200)
        self.assertEqual(f.cloud.add_record.call_args.args[1]["TTL"], 120)
        self.assertEqual(f.cloud.add_record.call_args.args[1]["Line"], "telecom")
        f.cloud.allowed_domains = {"example.com"}
        self.assertEqual(f.client.get("/dnsmanager/accounts/test?account=" + f.account_id, headers={"X-Test-User": "reader"}).status_code, 200)
        self.assertEqual(
            f.client.get(
                "/dnsmanager/records/test?account=" + f.account_id + "&domain=example.com&record_id=123&remaining=0", headers={"X-Test-User": "reader"}
            ).status_code,
            400,
        )
