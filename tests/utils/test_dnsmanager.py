"""Encrypted persistence and HTTP permission/intent tests without cloud writes."""

import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
import sqlite3
import shutil
from pathlib import Path
from uuid import uuid4
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet
from flask import Flask
from flask_login import LoginManager, UserMixin
from flask_wtf.csrf import CSRFProtect
from jinja2 import DictLoader

ROOT = Path(__file__).resolve().parents[2]
BLUEPRINTS = ROOT / "misc/plugins/dnsmanager/ui/blueprints"
sys.path[:0] = [str(ROOT / "src/common/utils"), str(BLUEPRINTS)]
from alidns import AliDNSError
from bw_dnsmanager.store import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.key = self.root / "key"
        self.key.write_bytes(Fernet.generate_key())
        self.key.chmod(0o600)
        self.store = Store(self.root / "data", self.key)
        self.account_id = str(uuid4())

    def save(self, revision=0):
        self.store.save_account(
            self.account_id,
            "Test account",
            ["example.com"],
            {"access_key_id": "fake-id", "access_key_secret": "secret-sentinel-123"},
            revision,
            "admin",
            str(uuid4()),
        )

    def test_credentials_encrypted_and_metadata_audit_do_not_return_secrets(self):
        self.save()
        data = self.store.path.read_bytes()
        self.assertNotIn(b"secret-sentinel-123", data)
        self.assertNotIn(b"fake-id", data)
        metadata = json.dumps({"accounts": self.store.accounts(), "audit": self.store.audit()})
        self.assertNotIn("secret-sentinel-123", metadata)
        self.assertNotIn("fake-id", metadata)
        self.assertEqual(self.store.accounts(masked=True)[0]["access_key_id_masked"], "fa••••id")
        self.assertEqual(self.store.accounts(masked=True)[0]["access_key_secret_masked"], "secr••••-123")
        self.assertEqual(self.store.account(self.account_id).allowed_domains, {"example.com"})
        reopened = Store(self.root / "data", self.key)
        self.assertEqual(reopened.accounts()[0]["id"], self.account_id)

    def test_provider_is_stored_and_returned(self):
        self.save()
        profile = self.store.accounts(masked=True)[0]
        self.assertEqual(profile["provider_id"], "alidns")
        self.assertEqual(profile["provider_name"], "Alibaba Cloud DNS")
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT provider_id FROM account_providers WHERE account_id=?", (self.account_id,)).fetchone()[0], "alidns")

    def test_legacy_account_without_provider_metadata_stays_usable(self):
        self.save()
        with self.store.connect() as db:
            before = db.execute("SELECT credentials FROM accounts WHERE id=?", (self.account_id,)).fetchone()[0]
            db.execute("DELETE FROM account_providers WHERE account_id=?", (self.account_id,))
        reopened = Store(self.root / "data", self.key)
        self.assertEqual(reopened.accounts()[0]["provider_id"], "alidns")
        self.assertEqual(reopened.account(self.account_id).allowed_domains, {"example.com"})
        with reopened.connect() as db:
            self.assertEqual(before, db.execute("SELECT credentials FROM accounts WHERE id=?", (self.account_id,)).fetchone()[0])

    def test_unknown_provider_is_rejected_without_writing(self):
        with self.assertRaisesRegex(AliDNSError, "UnsupportedProvider"):
            self.store.save_account(
                self.account_id,
                "Unsupported",
                ["example.com"],
                {"access_key_id": "fake-id", "access_key_secret": "fake-secret"},
                0,
                "admin",
                str(uuid4()),
                "not-installed",
            )
        self.assertEqual(self.store.accounts(), [])

    def test_registered_adapter_controls_validation_masking_and_client(self):
        from bw_dnsmanager.providers import PROVIDERS, public_providers

        factory = Mock()
        descriptor = {
            "id": "fixture",
            "name": "Fixture Provider",
            "fields": [{"key": "api_token", "id": "fixture-token", "label": "API token", "required": True}],
            "validate": lambda api_token: types.SimpleNamespace(api_token=api_token),
            "client": factory,
        }
        with patch.dict(PROVIDERS, {"fixture": descriptor}):
            self.store.save_account(self.account_id, "Fixture", ["example.com"], {"api_token": "fixture-token-data"}, 0, "admin", str(uuid4()), "fixture")
            self.store.account(self.account_id)
            self.assertEqual(factory.call_args.args[0].api_token, "fixture-token-data")
            self.assertEqual(self.store.accounts(masked=True)[0]["api_token_masked"], "fixt••••data")
            self.assertEqual(public_providers()[-1]["fields"][0]["key"], "api_token")
            self.assertNotIn("fixture-token-data", json.dumps(self.store.accounts(masked=True)))

    def test_changing_legacy_provider_requires_new_credentials(self):
        from bw_dnsmanager.providers import PROVIDERS

        self.save()
        with self.store.connect() as db:
            db.execute("DELETE FROM account_providers WHERE account_id=?", (self.account_id,))
        with patch.dict(PROVIDERS, {"fixture": {"id": "fixture"}}):
            with self.assertRaisesRegex(AliDNSError, "InvalidCredentials"):
                self.store.save_account(self.account_id, "Changed", ["example.com"], None, 1, "admin", str(uuid4()), "fixture")
        self.assertEqual(self.store.accounts()[0]["provider_id"], "alidns")

    def test_old_revision_cannot_overwrite_account(self):
        self.save()
        with self.assertRaisesRegex(AliDNSError, "AccountChanged"):
            self.save()
        self.assertEqual(self.store.accounts()[0]["revision"], 1)

    def test_wrong_key_fails_without_resetting_existing_data(self):
        self.save()
        self.key.write_bytes(Fernet.generate_key())
        reopened = Store(self.root / "data", self.key)
        with self.assertRaisesRegex(AliDNSError, "CredentialDecryptionFailed"):
            reopened.account(self.account_id)
        self.assertEqual(len(reopened.accounts()), 1)

    def test_sqlite_backup_and_separate_key_restore_credentials_and_audit(self):
        self.save()
        restore = self.root / "restore"
        restore.mkdir(mode=0o700)
        target = sqlite3.connect(restore / "state.sqlite3")
        try:
            with self.store.connect() as source:
                source.backup(target)
        finally:
            target.close()
        (restore / "state.sqlite3").chmod(0o600)
        key = self.root / "restored-key"
        shutil.copyfile(self.key, key)
        key.chmod(0o600)
        reopened = Store(restore, key)
        self.assertEqual(reopened.account(self.account_id).allowed_domains, {"example.com"})
        self.assertEqual(reopened.audit()[0]["action"], "account.save")

    def test_short_masks_never_reveal_the_complete_value(self):
        for value in ("a", "ab", "abcd", "abcde", "12345678"):
            self.assertNotIn(value, self.store.mask(value))
        self.assertEqual(self.store.mask(""), "未配置")

    def test_metadata_update_preserves_encrypted_credentials(self):
        self.save()
        with self.store.connect() as db:
            before = db.execute("SELECT credentials FROM accounts WHERE id=?", (self.account_id,)).fetchone()[0]
        self.store.save_account(self.account_id, "Renamed", ["other.example.com"], None, 1, "admin", str(uuid4()))
        with self.store.connect() as db:
            after = db.execute("SELECT credentials FROM accounts WHERE id=?", (self.account_id,)).fetchone()[0]
            self.assertEqual(len(list(db.execute("PRAGMA table_info(accounts)"))), 6)
        self.assertEqual(before, after)
        self.assertEqual(self.store.accounts()[0]["domains"], ["other.example.com"])
        self.assertFalse(self.store.audit()[0]["intent"]["credentials_rotated"])

    def test_new_account_requires_credentials(self):
        with self.assertRaisesRegex(AliDNSError, "InvalidCredentials"):
            self.store.save_account(self.account_id, "New", ["example.com"], None, 0, "admin", str(uuid4()))
        self.assertEqual(self.store.accounts(), [])

    def test_old_revision_cannot_delete_account(self):
        self.save()
        self.save(revision=1)
        with self.assertRaisesRegex(AliDNSError, "AccountChanged"):
            self.store.delete_account(self.account_id, 1, "admin", str(uuid4()))
        self.assertEqual(len(self.store.accounts()), 1)

    def test_unresolved_operation_prevents_account_deletion(self):
        self.save()
        operation_id = str(uuid4())
        self.store.begin(operation_id, "operator", self.account_id, "record.add", {})
        for status in ("PENDING", "UNKNOWN"):
            if status == "UNKNOWN":
                self.store.finish(operation_id, status, {})
            with self.assertRaisesRegex(AliDNSError, "AccountHasUnresolvedOperations"):
                self.store.delete_account(self.account_id, 1, "admin", str(uuid4()))
        self.assertEqual(len(self.store.accounts()), 1)

    def test_pending_intent_survives_reopen_and_duplicate_is_not_replayed(self):
        operation_id = str(uuid4())
        self.store.begin(operation_id, "operator", self.account_id, "record.add", {"domain": "example.com"})
        reopened = Store(self.root / "data", self.key)
        self.assertEqual(reopened.audit()[0]["status"], "PENDING")
        with self.assertRaisesRegex(AliDNSError, "DuplicateOperation"):
            reopened.begin(operation_id, "operator", self.account_id, "record.add", {})
        reopened.finish(operation_id, "UNKNOWN", {"error": "Timeout"})
        self.assertEqual(reopened.audit()[0]["status"], "UNKNOWN")

    def test_concurrent_writer_is_rejected_and_lock_released(self):
        with self.store.mutation_lock(self.account_id):
            with self.assertRaisesRegex(AliDNSError, "OperationInProgress"):
                with self.store.mutation_lock(self.account_id):
                    self.fail("second writer acquired lock")
        with self.store.mutation_lock(self.account_id):
            pass

    def test_world_readable_key_is_rejected(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(AliDNSError, "CredentialStoreNotConfigured"):
            Store(self.root / "other", self.key)


class User(UserMixin):
    def __init__(self, role):
        self.id = role
        self.admin = role == "admin"
        self.list_permissions = ["read"] if role == "reader" else ["read", "write"]


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dependency = types.ModuleType("app.dependencies")
        dependency.DB = types.SimpleNamespace(readonly=False)
        cls.db = dependency.DB
        with patch.dict(sys.modules, {"app": types.ModuleType("app"), "app.dependencies": dependency}):
            spec = importlib.util.spec_from_file_location("dnsmanager_plugin_test", BLUEPRINTS / "dnsmanager.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        cls.module = module

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        key = self.root / "key"
        key.write_bytes(Fernet.generate_key())
        key.chmod(0o600)
        environment = patch.dict(os.environ, {"BUNKERWEB_DNSMANAGER_DATA_DIR": str(self.root / "data"), "BUNKERWEB_DNSMANAGER_KEY_FILE": str(key)})
        environment.start()
        self.addCleanup(environment.stop)
        self.db.readonly = False
        app = Flask(__name__)
        app.config.update(SECRET_KEY="unit-test-session-only", TESTING=True)
        app.jinja_loader = DictLoader({"dashboard.html": "{% block content %}{% endblock %}{% block scripts %}{% endblock %}"})
        app.register_blueprint(self.module.dnsmanager)
        login = LoginManager(app)

        @login.request_loader
        def load_user(request):
            role = request.headers.get("X-Test-User")
            return User(role) if role in {"reader", "writer", "admin"} else None

        CSRFProtect(app)
        self.app = app
        self.client = app.test_client()
        self.store = Store()
        self.account_id = str(uuid4())
        self.store.save_account(
            self.account_id, "Acceptance", ["example.com"], {"access_key_id": "fake-id", "access_key_secret": "fake-secret"}, 0, "admin", str(uuid4())
        )
        self.cloud = Mock()
        self.cloud._domain.return_value = "example.com"
        self.cloud._record_values.side_effect = lambda values: values
        self.cloud.add_record.return_value = {"RecordId": "123", "RequestId": "cloud-request-1"}
        self.account_patch = patch.object(Store, "account", return_value=self.cloud)
        self.account_patch.start()
        self.addCleanup(self.account_patch.stop)

    def csrf(self, role="admin"):
        result = self.client.get("/dnsmanager", headers={"X-Test-User": role})
        self.assertEqual(result.status_code, 200)
        import re

        return re.search(r'id="dns-csrf" value="([^"]+)"', result.get_data(as_text=True)).group(1)

    def write(self, role="admin", token=True, **extra):
        headers = {"X-Test-User": role}
        if token:
            headers["X-CSRFToken"] = self.csrf(role)
        data = {
            "account": self.account_id,
            "operation_id": str(uuid4()),
            "domain": "example.com",
            "action": "add",
            "confirmed": True,
            "values": {"RR": "acceptance", "Type": "TXT", "Value": "test"},
            **extra,
        }
        return self.client.post("/dnsmanager/records/write", json=data, headers=headers)

    def test_login_required_for_page_and_queries(self):
        self.assertEqual(self.client.get("/dnsmanager").status_code, 401)
        self.assertEqual(self.client.get("/dnsmanager/accounts").status_code, 401)

    def test_page_urls_survive_host_jinja_url_wrapper(self):
        self.app.jinja_env.globals["url_for"] = lambda *args, **kwargs: "#"
        result = self.client.get("/dnsmanager", headers={"X-Test-User": "reader"})
        text = result.get_data(as_text=True)
        self.assertIn('data-base="/dnsmanager"', text)
        self.assertIn('src="/dnsmanager/static/dnsmanager.js?v=', text)
        self.assertIn("no-store", result.headers["Cache-Control"])
        with self.client.get("/dnsmanager/static/dnsmanager.js") as asset:
            self.assertEqual(asset.status_code, 200)

    def test_readonly_user_and_readonly_database_cannot_write(self):
        self.assertEqual(self.write("reader").status_code, 403)
        self.db.readonly = True
        self.assertEqual(self.write("admin").status_code, 403)
        self.cloud.add_record.assert_not_called()

    def test_missing_csrf_cannot_write(self):
        self.assertEqual(self.write(token=False).status_code, 400)
        self.cloud.add_record.assert_not_called()

    def test_writer_can_write_but_cannot_save_credentials(self):
        self.assertEqual(self.write("writer").status_code, 200)
        token = self.csrf("writer")
        result = self.client.post("/dnsmanager/accounts/save", json={}, headers={"X-Test-User": "writer", "X-CSRFToken": token})
        self.assertEqual(result.status_code, 403)

    def save_account_request(self):
        return self.client.post(
            "/dnsmanager/accounts/save",
            json={
                "id": self.account_id,
                "label": "Updated",
                "domains": ["example.com"],
                "credentials": {"access_key_id": "rotated-id", "access_key_secret": "rotated-secret"},
                "revision": 1,
                "operation_id": str(uuid4()),
            },
            headers={"X-Test-User": "admin", "X-CSRFToken": self.csrf()},
        )

    def test_admin_can_rotate_credentials_without_reading_them_back(self):
        self.assertEqual(self.save_account_request().status_code, 200)
        result = self.client.get("/dnsmanager/accounts", headers={"X-Test-User": "admin"})
        self.assertEqual(result.json["accounts"][0]["revision"], 2)
        self.assertNotIn("rotated-secret", result.get_data(as_text=True))
        self.assertEqual(result.json["accounts"][0]["access_key_secret_masked"], "rota••••cret")

    def test_admin_can_delete_account_without_deleting_cloud_records(self):
        token = self.csrf()
        result = self.client.post(
            "/dnsmanager/accounts/delete",
            json={"id": self.account_id, "revision": 1, "operation_id": str(uuid4())},
            headers={"X-Test-User": "admin", "X-CSRFToken": token},
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.client.get("/dnsmanager/accounts", headers={"X-Test-User": "admin"}).json["accounts"], [])
        self.cloud.delete_record.assert_not_called()

    def test_admin_metadata_edit_does_not_require_rotating_keys(self):
        token = self.csrf()
        response = self.client.post(
            "/dnsmanager/accounts/save",
            json={"id": self.account_id, "label": "Metadata only", "domains": ["example.com"], "revision": 1, "operation_id": str(uuid4())},
            headers={"X-Test-User": "admin", "X-CSRFToken": token},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.store.accounts()[0]["label"], "Metadata only")

    def test_masks_are_admin_only_and_complete_values_never_returned(self):
        for role in ("reader", "writer", "admin"):
            response = self.client.get("/dnsmanager/accounts", headers={"X-Test-User": role})
            profile = response.json["accounts"][0]
            self.assertEqual("access_key_id_masked" in profile, role == "admin")
            self.assertNotIn("fake-secret", response.get_data(as_text=True))
            self.assertNotIn("fake-id", response.get_data(as_text=True))
            self.assertNotIn("credentials", profile)

    def test_account_delete_requires_admin_csrf_and_writable_database(self):
        values = {"id": self.account_id, "revision": 1, "operation_id": str(uuid4())}
        for role in ("reader", "writer"):
            result = self.client.post("/dnsmanager/accounts/delete", json=values, headers={"X-Test-User": role, "X-CSRFToken": self.csrf(role)})
            self.assertEqual(result.status_code, 403)
        self.assertEqual(self.client.post("/dnsmanager/accounts/delete", json=values, headers={"X-Test-User": "admin"}).status_code, 400)
        token = self.csrf()
        self.db.readonly = True
        self.assertEqual(self.client.post("/dnsmanager/accounts/delete", json=values, headers={"X-Test-User": "admin", "X-CSRFToken": token}).status_code, 403)
        self.assertEqual(len(self.store.accounts()), 1)

    def test_account_delete_cannot_race_record_mutation(self):
        token = self.csrf()
        with self.store.mutation_lock(self.account_id):
            result = self.client.post(
                "/dnsmanager/accounts/delete",
                json={"id": self.account_id, "revision": 1, "operation_id": str(uuid4())},
                headers={"X-Test-User": "admin", "X-CSRFToken": token},
            )
            self.assertEqual(result.status_code, 409)
        self.assertEqual(len(self.store.accounts()), 1)

    def test_http_account_save_validates_and_persists_provider(self):
        payload = {
            "id": self.account_id,
            "label": "Provider selected",
            "domains": ["example.com"],
            "credentials": None,
            "revision": 1,
            "operation_id": str(uuid4()),
            "provider_id": "not-installed",
        }
        headers = {"X-Test-User": "admin", "X-CSRFToken": self.csrf()}
        self.assertEqual(self.client.post("/dnsmanager/accounts/save", json=payload, headers=headers).status_code, 400)
        payload["provider_id"] = "alidns"
        self.assertEqual(self.client.post("/dnsmanager/accounts/save", json=payload, headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/dnsmanager/accounts", headers={"X-Test-User": "admin"}).json["accounts"][0]["provider_id"], "alidns")

    def test_account_changes_cannot_race_record_mutation(self):
        with self.store.mutation_lock(self.account_id):
            self.assertEqual(self.save_account_request().status_code, 409)
        self.assertEqual(self.store.accounts()[0]["revision"], 1)

    def test_intent_is_durable_before_cloud_write(self):
        def add(*args):
            row = self.store.audit()[0]
            self.assertEqual(row["status"], "PENDING")
            self.assertEqual(row["intent"]["after"]["RR"], "acceptance")
            return {"RecordId": "123"}

        self.cloud.add_record.side_effect = add
        self.assertEqual(self.write().status_code, 200)
        self.assertEqual(self.store.audit()[0]["status"], "SUCCEEDED")

    def test_duplicate_request_never_repeats_cloud_write(self):
        operation_id = str(uuid4())
        self.assertEqual(self.write(operation_id=operation_id).status_code, 200)
        self.assertEqual(self.write(operation_id=operation_id).status_code, 409)
        self.assertEqual(self.cloud.add_record.call_count, 1)

    def test_unknown_write_outcome_retained_in_audit(self):
        self.cloud.add_record.side_effect = AliDNSError("SDKRequestFailed", outcome_unknown=True)
        result = self.write()
        self.assertTrue(result.json["outcome_unknown"])
        self.assertEqual(self.store.audit()[0]["status"], "UNKNOWN")

    def test_failed_success_receipt_keeps_pending_and_reports_unknown(self):
        with patch.object(Store, "finish", side_effect=OSError("fake-secret")):
            result = self.write()
        self.assertTrue(result.json["outcome_unknown"])
        self.assertNotIn("fake-secret", result.get_data(as_text=True))
        self.assertEqual(self.store.audit()[0]["status"], "PENDING")

    def test_accounts_and_audit_never_return_credentials(self):
        for url in ("/dnsmanager/accounts", "/dnsmanager/audit"):
            result = self.client.get(url, headers={"X-Test-User": "reader"})
            self.assertEqual(result.status_code, 200)
            self.assertNotIn("fake-secret", result.get_data(as_text=True))
            self.assertNotIn("fake-id", result.get_data(as_text=True))

    def test_missing_key_affects_plugin_api_without_crashing_page(self):
        with patch.dict(os.environ, {"BUNKERWEB_DNSMANAGER_KEY_FILE": str(self.root / "missing")}):
            result = self.client.get("/dnsmanager/accounts", headers={"X-Test-User": "reader"})
            self.assertEqual(result.status_code, 503)
            self.assertEqual(self.client.get("/dnsmanager", headers={"X-Test-User": "reader"}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
