"""Scoped DNS management adapter over the official Alibaba Cloud SDK.

No background synchronization and no automatic retries of mutations. AliDNS does
not offer compare-and-swap for record updates: the pre-write fingerprint check
detects stale forms, but is not an atomic lock against other cloud writers.
"""

from dataclasses import dataclass, field
from hashlib import sha256
from hmac import compare_digest
from json import dumps
from re import fullmatch
from typing import Mapping

from alibabacloud_alidns20150109.client import Client as SDKClient
from alibabacloud_alidns20150109 import models
from alibabacloud_tea_openapi.utils_models import Config
from darabonba.runtime import RuntimeOptions
from darabonba.policy.retry import RetryOptions
from darabonba.exceptions import ResponseException


class AliDNSError(Exception):
    """Safe error: never embed request bodies, credentials or provider messages."""

    def __init__(self, code: str, request_id: str = "", outcome_unknown: bool = False):
        self.code = code if isinstance(code, str) and fullmatch(r"[A-Za-z0-9_.-]{1,128}", code) else "ProviderError"
        self.request_id = request_id if isinstance(request_id, str) and fullmatch(r"[A-Za-z0-9-]{1,128}", request_id) else ""
        self.outcome_unknown = outcome_unknown
        super().__init__(self.code)


@dataclass(frozen=True)
class AliDNSCredentials:
    access_key_id: str = field(repr=False)
    access_key_secret: str = field(repr=False)
    security_token: str = field(default="", repr=False)

    def __post_init__(self):
        if not self.access_key_id or not self.access_key_secret:
            raise AliDNSError("MissingCredentials")


def record_fingerprint(record: Mapping) -> str:
    """Opaque stale-form token; include every mutable field used by this client."""
    fields = ("DomainName", "RecordId", "RR", "Type", "Value", "TTL", "Line", "Priority", "Status")
    values = {key: str(record.get(key, "")) for key in fields}
    return sha256(dumps(values, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


class AliDNSClient:
    ENDPOINT = "alidns.aliyuncs.com"
    READ_ACTIONS = frozenset({"DescribeDomains", "DescribeDomainRecords", "DescribeDomainRecordInfo"})
    WRITE_ACTIONS = frozenset({"AddDomainRecord", "UpdateDomainRecord", "DeleteDomainRecord", "SetDomainRecordStatus"})
    RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "REDIRECT_URL", "FORWARD_URL"})

    def __init__(self, credentials: AliDNSCredentials, allowed_domains):
        self._credentials = credentials
        self.allowed_domains = frozenset(self._normalize_domain(domain) for domain in allowed_domains)
        if not self.allowed_domains:
            raise AliDNSError("EmptyDomainScope")
        self._sdk = SDKClient(
            Config(
                access_key_id=credentials.access_key_id,
                access_key_secret=credentials.access_key_secret,
                security_token=credentials.security_token or None,
                endpoint=self.ENDPOINT,
                region_id="cn-hangzhou",
                protocol="HTTPS",
                retry_options=RetryOptions(retryable=False),
            )
        )
        self._runtime = RuntimeOptions(connect_timeout=5000, read_timeout=20000, ignore_ssl=False)

    @staticmethod
    def _normalize_domain(value):
        if not isinstance(value, str):
            raise AliDNSError("InvalidDomain")
        try:
            domain = value.rstrip(".").encode("idna").decode().lower()
        except UnicodeError:
            raise AliDNSError("InvalidDomain") from None
        labels = domain.split(".")
        if len(domain) > 253 or len(labels) < 2 or any(not fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise AliDNSError("InvalidDomain")
        return domain

    def _domain(self, value):
        domain = self._normalize_domain(value)
        if domain not in self.allowed_domains:
            raise AliDNSError("DomainOutsideScope")
        return domain

    @staticmethod
    def _page(page, page_size):
        if type(page) is not int or page < 1 or page > 1_000_000 or type(page_size) is not int or not 1 <= page_size <= 500:
            raise AliDNSError("InvalidPagination")
        return {"PageNumber": page, "PageSize": page_size}

    def _call(self, action, **arguments):
        if action not in self.READ_ACTIONS | self.WRITE_ACTIONS:
            raise AliDNSError("UnsupportedAction")
        writing = action in self.WRITE_ACTIONS
        # Use the SDK's request models, signatures and HTTPS transport. Only our
        # explicit operation allowlist is exposed to the plugin.
        request_model = getattr(models, action + "Request")().from_map(arguments)
        method = {
            "DescribeDomains": "describe_domains_with_options",
            "DescribeDomainRecords": "describe_domain_records_with_options",
            "DescribeDomainRecordInfo": "describe_domain_record_info_with_options",
            "AddDomainRecord": "add_domain_record_with_options",
            "UpdateDomainRecord": "update_domain_record_with_options",
            "DeleteDomainRecord": "delete_domain_record_with_options",
            "SetDomainRecordStatus": "set_domain_record_status_with_options",
        }[action]
        try:
            body = getattr(self._sdk, method)(request_model, self._runtime).body
            payload = body.to_map() if body is not None else None
        except ResponseException as exc:
            data = exc.data if isinstance(exc.data, dict) else {}
            status = exc.status_code or 0
            raise AliDNSError(exc.code, data.get("RequestId", ""), outcome_unknown=writing and (status >= 500 or not status)) from None
        except Exception:
            # Transport errors can contain signed URLs or credential details.
            raise AliDNSError("SDKRequestFailed", outcome_unknown=writing) from None
        if not isinstance(payload, dict):
            raise AliDNSError("InvalidProviderResponse", outcome_unknown=writing)
        if writing and not fullmatch(r"[0-9]{1,64}", str(payload.get("RecordId", ""))):
            raise AliDNSError("InvalidProviderResponse", payload.get("RequestId", ""), outcome_unknown=True)
        return payload

    def list_domains(self, page=1, page_size=100):
        payload = self._call("DescribeDomains", **self._page(page, page_size))
        # Keep provider pagination: a filtered page may be empty before the last page.
        payload["Domains"] = {"Domain": [item for item in payload.get("Domains", {}).get("Domain", []) if item.get("DomainName") in self.allowed_domains]}
        return payload

    def list_records(self, domain, page=1, page_size=100):
        return self._call("DescribeDomainRecords", DomainName=self._domain(domain), **self._page(page, page_size))

    def get_record(self, domain, record_id):
        domain = self._domain(domain)
        if not isinstance(record_id, str) or not fullmatch(r"[0-9]{1,64}", record_id):
            raise AliDNSError("InvalidRecordId")
        record = self._call("DescribeDomainRecordInfo", RecordId=record_id)
        if record.get("DomainName") != domain or str(record.get("RecordId", "")) != record_id:
            raise AliDNSError("RecordOutsideScope")
        return record

    @classmethod
    def _record_values(cls, values):
        if not isinstance(values, dict) or set(values) - {"RR", "Type", "Value", "TTL", "Line", "Priority"}:
            raise AliDNSError("InvalidRecordFields")
        result = dict(values)
        for key, limit in (("RR", 253), ("Type", 32), ("Value", 4096), ("Line", 128)):
            value = result.get(key, "default" if key == "Line" else "")
            if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(char) < 32 for char in value):
                raise AliDNSError("InvalidRecordFields")
            result[key] = value
        if result["Type"] not in cls.RECORD_TYPES:
            raise AliDNSError("UnsupportedRecordType")
        ttl = result.get("TTL", 600)
        if type(ttl) is not int or not 1 <= ttl <= 604800:
            raise AliDNSError("InvalidTTL")
        result["TTL"] = ttl
        if "Priority" in result and (type(result["Priority"]) is not int or not 1 <= result["Priority"] <= 50):
            raise AliDNSError("InvalidPriority")
        if result["Type"] == "MX" and "Priority" not in result:
            raise AliDNSError("MissingMXPriority")
        return result

    def add_record(self, domain, values):
        return self._call("AddDomainRecord", DomainName=self._domain(domain), **self._record_values(values))

    def _check_current(self, domain, record_id, expected_fingerprint):
        record = self.get_record(domain, record_id)
        if not isinstance(expected_fingerprint, str) or not fullmatch(r"[0-9a-f]{64}", expected_fingerprint):
            raise AliDNSError("MissingRecordFingerprint")
        if not compare_digest(record_fingerprint(record), expected_fingerprint):
            raise AliDNSError("RecordChanged")
        return record

    def update_record(self, domain, record_id, values, expected_fingerprint):
        values = self._record_values(values)
        self._check_current(domain, record_id, expected_fingerprint)
        return self._call("UpdateDomainRecord", RecordId=record_id, **values)

    def delete_record(self, domain, record_id, expected_fingerprint):
        self._check_current(domain, record_id, expected_fingerprint)
        return self._call("DeleteDomainRecord", RecordId=record_id)

    def set_record_status(self, domain, record_id, status, expected_fingerprint):
        if status not in {"ENABLE", "DISABLE"}:
            raise AliDNSError("InvalidStatus")
        self._check_current(domain, record_id, expected_fingerprint)
        return self._call("SetDomainRecordStatus", RecordId=record_id, Status=status)
