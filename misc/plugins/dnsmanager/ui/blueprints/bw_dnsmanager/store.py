"""Control-plane-only encrypted account storage and durable write intents."""

import json
import os
import sqlite3
import stat
import fcntl
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from alidns import AliDNSError, AliDNSClient
from .providers import DEFAULT_PROVIDER, provider, validate_credentials, validate_options


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, directory=None, key_file=None):
        self.directory = Path(directory or os.getenv("BUNKERWEB_DNSMANAGER_DATA_DIR", "/var/lib/bunkerweb-dnsmanager"))
        key_path = Path(key_file or os.getenv("BUNKERWEB_DNSMANAGER_KEY_FILE", "/run/secrets/bunkerweb-dnsmanager/key"))
        try:
            fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o027 or info.st_size > 128:
                    raise ValueError()
                self._cipher = Fernet(os.read(fd, 129).strip())
            finally:
                os.close(fd)
        except (OSError, ValueError):
            raise AliDNSError("CredentialStoreNotConfigured") from None
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_mode & 0o007:
            raise AliDNSError("UnsafeCredentialDirectory")
        self.path = self.directory / "state.sqlite3"
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_mode & 0o077:
                raise AliDNSError("UnsafeCredentialDatabase")
        finally:
            os.close(fd)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY, label TEXT NOT NULL, domains TEXT NOT NULL,
                    credentials BLOB NOT NULL, revision INTEGER NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS account_providers (
                    account_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS account_options (account_id TEXT PRIMARY KEY, options TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL, account_id TEXT NOT NULL,
                    action TEXT NOT NULL, intent TEXT NOT NULL, status TEXT NOT NULL,
                    result TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT
                );
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def identifier(value):
        try:
            if not isinstance(value, str) or str(UUID(value)) != value:
                raise ValueError()
        except ValueError:
            raise AliDNSError("InvalidIdentifier") from None
        return value

    def accounts(self, masked=False):
        columns = "a.id,a.label,a.domains,a.revision,a.updated_at,COALESCE(p.provider_id,'alidns') AS provider_id" + (",a.credentials" if masked else "")
        with self.connect() as db:
            rows = db.execute(f"SELECT {columns} FROM accounts a LEFT JOIN account_providers p ON a.id=p.account_id ORDER BY a.label,a.id").fetchall()
        profiles = []
        for row in rows:
            profile = dict(row)
            profile["domains"] = json.loads(row["domains"])
            definition = provider(profile["provider_id"])
            profile["provider_name"] = definition["name"]
            profile["options"] = self.options(profile["id"], profile["provider_id"])
            if masked:
                encrypted = profile.pop("credentials")
                try:
                    values = json.loads(self._cipher.decrypt(encrypted))
                    profile["credential_status"] = "configured"
                    for field in definition["fields"]:
                        profile[field["key"] + "_masked"] = self.mask(values.get(field["key"], ""))
                except (InvalidToken, ValueError, TypeError, AttributeError):
                    profile["credential_status"] = "unavailable"
            profiles.append(profile)
        return profiles

    @staticmethod
    def mask(value):
        if not value:
            return "未配置"
        # Short credentials must never be reconstructable from both ends.
        if len(value) <= 4:
            return "••••"
        visible = 4 if len(value) > 12 else 2
        return value[:visible] + "••••" + value[-visible:]

    def options(self, account_id, provider_id):
        with self.connect() as db:
            row = db.execute("SELECT options FROM account_options WHERE account_id=?", (account_id,)).fetchone()
        return validate_options(provider_id, json.loads(row[0]) if row else None)

    def account(self, account_id):
        self.identifier(account_id)
        with self.connect() as db:
            row = db.execute(
                "SELECT a.*,COALESCE(p.provider_id,'alidns') AS provider_id FROM accounts a LEFT JOIN account_providers p ON a.id=p.account_id WHERE a.id=?",
                (account_id,),
            ).fetchone()
        if row is None:
            raise AliDNSError("AccountNotFound")
        try:
            options = self.options(account_id, row["provider_id"])
            credentials = validate_credentials(row["provider_id"], json.loads(self._cipher.decrypt(row["credentials"])), options)
        except (InvalidToken, ValueError, TypeError):
            raise AliDNSError("CredentialDecryptionFailed") from None
        factory = provider(row["provider_id"])["client"]
        return (
            factory(credentials, json.loads(row["domains"]), options=options)
            if provider(row["provider_id"]).get("options")
            else factory(credentials, json.loads(row["domains"]))
        )

    def save_account(self, account_id, label, domains, credentials, revision, actor, operation_id, provider_id=None, options=None):
        self.identifier(account_id)
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 128 or not isinstance(domains, list) or not 1 <= len(domains) <= 200:
            raise AliDNSError("InvalidAccount")
        domains = sorted(set(AliDNSClient._normalize_domain(domain) for domain in domains))
        if type(revision) is not int or revision < 0:
            raise AliDNSError("InvalidRevision")
        self.identifier(operation_id)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            before = db.execute("SELECT label,domains,revision,credentials FROM accounts WHERE id=?", (account_id,)).fetchone()
            if (before is None and revision != 0) or (before is not None and before["revision"] != revision):
                raise AliDNSError("AccountChanged")
            previous_provider = db.execute("SELECT provider_id FROM account_providers WHERE account_id=?", (account_id,)).fetchone()
            selected_provider = provider_id if provider_id is not None else (previous_provider[0] if previous_provider else DEFAULT_PROVIDER)
            provider(selected_provider)
            previous_options = db.execute("SELECT options FROM account_options WHERE account_id=?", (account_id,)).fetchone()
            selected_options = validate_options(
                selected_provider,
                (
                    options
                    if options is not None
                    else (
                        json.loads(previous_options[0])
                        if previous_options and (previous_provider[0] if previous_provider else DEFAULT_PROVIDER) == selected_provider
                        else None
                    )
                ),
            )
            if credentials is None:
                if before is None or selected_provider != (previous_provider[0] if previous_provider else DEFAULT_PROVIDER):
                    raise AliDNSError("InvalidCredentials")
                encrypted = before["credentials"]
                try:
                    validate_credentials(selected_provider, json.loads(self._cipher.decrypt(encrypted)), selected_options)
                except InvalidToken:
                    raise AliDNSError("CredentialDecryptionFailed") from None
            else:
                validate_credentials(selected_provider, credentials, selected_options)
                encrypted = self._cipher.encrypt(json.dumps(credentials).encode())
            previous = {key: before[key] for key in ("label", "domains", "revision")} if before else None
            if previous is not None:
                previous["provider_id"] = previous_provider[0] if previous_provider else DEFAULT_PROVIDER
                previous["options"] = json.loads(previous_options[0]) if previous_options else None
            intent = {
                "before": previous,
                "after": {"label": label.strip(), "domains": domains, "revision": revision + 1, "provider_id": selected_provider, "options": selected_options},
                "credentials_rotated": credentials is not None,
            }
            self._insert_intent(db, operation_id, actor, account_id, "account.save", intent)
            db.execute(
                "INSERT INTO accounts VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET label=excluded.label,domains=excluded.domains,credentials=excluded.credentials,revision=excluded.revision,updated_at=excluded.updated_at",
                (account_id, label.strip(), json.dumps(domains), encrypted, revision + 1, now()),
            )
            db.execute(
                "INSERT INTO account_providers VALUES (?,?) ON CONFLICT(account_id) DO UPDATE SET provider_id=excluded.provider_id",
                (account_id, selected_provider),
            )
            db.execute(
                "INSERT INTO account_options VALUES (?,?) ON CONFLICT(account_id) DO UPDATE SET options=excluded.options",
                (account_id, json.dumps(selected_options)),
            )
            db.execute("UPDATE audit SET status='SUCCEEDED',finished_at=? WHERE id=?", (now(), operation_id))

    def delete_account(self, account_id, revision, actor, operation_id):
        self.identifier(account_id)
        if type(revision) is not int or revision < 1:
            raise AliDNSError("InvalidRevision")
        self.identifier(operation_id)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            before = db.execute("SELECT label,domains,revision FROM accounts WHERE id=?", (account_id,)).fetchone()
            if before is None:
                raise AliDNSError("AccountNotFound")
            if before["revision"] != revision:
                raise AliDNSError("AccountChanged")
            if db.execute("SELECT 1 FROM audit WHERE account_id=? AND status IN ('PENDING','UNKNOWN') LIMIT 1", (account_id,)).fetchone():
                raise AliDNSError("AccountHasUnresolvedOperations")
            self._insert_intent(db, operation_id, actor, account_id, "account.delete", {"before": dict(before), "after": None})
            db.execute("DELETE FROM account_options WHERE account_id=?", (account_id,))
            db.execute("DELETE FROM account_providers WHERE account_id=?", (account_id,))
            db.execute("DELETE FROM accounts WHERE id=?", (account_id,))
            db.execute("UPDATE audit SET status='SUCCEEDED',finished_at=? WHERE id=?", (now(), operation_id))

    @staticmethod
    def _insert_intent(db, operation_id, actor, account_id, action, intent):
        try:
            db.execute("INSERT INTO audit VALUES (?,?,?,?,?,'PENDING','{}',?,NULL)", (operation_id, str(actor), account_id, action, json.dumps(intent), now()))
        except sqlite3.IntegrityError:
            raise AliDNSError("DuplicateOperation") from None

    def begin(self, operation_id, actor, account_id, action, intent):
        self.identifier(operation_id)
        with self.connect() as db:
            self._insert_intent(db, operation_id, actor, account_id, action, intent)

    @contextmanager
    def mutation_lock(self, account_id):
        self.identifier(account_id)
        fd = os.open(self.directory / f"{account_id}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AliDNSError("OperationInProgress") from None
            yield
        finally:
            os.close(fd)

    def finish(self, operation_id, status, result):
        if status not in {"SUCCEEDED", "REJECTED", "UNKNOWN"}:
            raise ValueError("Invalid audit status")
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE audit SET status=?,result=?,finished_at=? WHERE id=? AND status='PENDING'", (status, json.dumps(result), now(), operation_id)
            )
            if cursor.rowcount != 1:
                raise AliDNSError("AuditStateChanged")

    def audit(self, page=1):
        if type(page) is not int or not 1 <= page <= 1_000_000:
            raise AliDNSError("InvalidPagination")
        with self.connect() as db:
            rows = db.execute("SELECT * FROM audit ORDER BY created_at DESC,id DESC LIMIT 50 OFFSET ?", ((page - 1) * 50,)).fetchall()
        return [dict(row) | {"intent": json.loads(row["intent"]), "result": json.loads(row["result"])} for row in rows]
