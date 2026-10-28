"""Account-level AliDNS options using the installed official SDKs."""

from dataclasses import dataclass, field
from alidns import AliDNSClient, AliDNSError, Config, SDKClient, RuntimeOptions, RetryOptions
from alibabacloud_credentials.client import Client as CredentialClient
from alibabacloud_credentials.models import Config as CredentialConfig


@dataclass(frozen=True)
class AccountCredentials:
    access_key_id: str = field(default="", repr=False)
    access_key_secret: str = field(default="", repr=False)
    security_token: str = field(default="", repr=False)
    ram_role: str = field(default="", repr=False)


class ConfiguredAliDNSClient(AliDNSClient):
    def __init__(self, credentials, allowed_domains, options=None):
        # Import lazily: providers imports this adapter while defining validation.
        from .providers import validate_options

        self.options = validate_options("alidns", options)
        self._credentials = credentials
        self.allowed_domains = frozenset(self._normalize_domain(domain) for domain in allowed_domains)
        if not self.allowed_domains:
            raise AliDNSError("EmptyDomainScope")
        timeout = self.options["http_timeout"] * 1000
        config = Config(endpoint=self.ENDPOINT, region_id=self.options["region_id"], protocol="HTTPS", retry_options=RetryOptions(retryable=False))
        if self.options["auth_mode"] == "ecs_ram_role":
            # Explicit provider; never fall back to an unrelated environment key.
            config.credential = CredentialClient(
                CredentialConfig(type="ecs_ram_role", role_name=credentials.ram_role, disable_imds_v1=True, timeout=timeout, connect_timeout=timeout)
            )
        else:
            config.access_key_id = credentials.access_key_id
            config.access_key_secret = credentials.access_key_secret
            config.security_token = credentials.security_token or None
        self._sdk = SDKClient(config)
        self._runtime = RuntimeOptions(connect_timeout=timeout, read_timeout=timeout, ignore_ssl=False)
