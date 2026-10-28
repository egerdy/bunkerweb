"""DNS provider registry. Only implemented adapters appear in the UI."""

from re import fullmatch

from alidns import AliDNSError
from .configured_alidns import AccountCredentials, ConfiguredAliDNSClient

DEFAULT_PROVIDER = "alidns"
PROVIDERS = {
    "alidns": {
        "id": "alidns",
        "name": "Alibaba Cloud DNS",
        "fields": [
            {"key": "access_key_id", "id": "key-id", "label": "AccessKey ID", "required": True, "auth_mode": "access_key"},
            {"key": "access_key_secret", "id": "key-secret", "label": "AccessKey Secret", "required": True, "auth_mode": "access_key"},
            {"key": "security_token", "id": "security-token", "label": "STS Token", "required": False, "auth_mode": "access_key"},
            {"key": "ram_role", "id": "ram-role", "label": "RAM Role", "required": True, "auth_mode": "ecs_ram_role"},
        ],
        "options": [
            {
                "key": "auth_mode",
                "label": "认证方式",
                "type": "select",
                "default": "access_key",
                "choices": [{"value": "access_key", "label": "AccessKey / STS"}, {"value": "ecs_ram_role", "label": "ECS RAM Role（需运行节点支持）"}],
            },
            {"key": "http_timeout", "label": "HTTP_TIMEOUT（API 超时，秒）", "type": "number", "default": 10, "min": 1, "max": 60},
            {"key": "region_id", "label": "REGION_ID", "type": "text", "default": "cn-hangzhou"},
            {"key": "line", "label": "LINE（新增记录默认线路）", "type": "text", "default": "default"},
            {"key": "ttl", "label": "TTL（新增记录默认秒数）", "type": "number", "default": 600, "min": 1, "max": 604800},
            {"key": "polling_interval", "label": "POLLING_INTERVAL（解析检测间隔，秒）", "type": "number", "default": 2, "min": 1, "max": 60},
            {"key": "propagation_timeout", "label": "PROPAGATION_TIMEOUT（解析检测等待，秒）", "type": "number", "default": 60, "min": 1, "max": 600},
        ],
        "validate": AccountCredentials,
        "client": ConfiguredAliDNSClient,
    }
}


def provider(value):
    if not isinstance(value, str) or value not in PROVIDERS:
        raise AliDNSError("UnsupportedProvider")
    return PROVIDERS[value]


def public_providers():
    return [{**{key: item[key] for key in ("id", "name", "fields")}, "options": item.get("options", [])} for item in PROVIDERS.values()]


def validate_options(provider_id, values=None):
    fields = provider(provider_id).get("options", [])
    if values is None:
        values = {}
    if not isinstance(values, dict) or set(values) - {field["key"] for field in fields}:
        raise AliDNSError("InvalidProviderOptions")
    result = {}
    for field in fields:
        key = field["key"]
        value = values.get(key, field["default"])
        if field["type"] == "number":
            if type(value) is not int or not field["min"] <= value <= field["max"]:
                raise AliDNSError("InvalidProviderOptions")
        elif not isinstance(value, str) or not fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
            raise AliDNSError("InvalidProviderOptions")
        if field["type"] == "select" and value not in {item["value"] for item in field["choices"]}:
            raise AliDNSError("InvalidProviderOptions")
        result[key] = value
    return result


def validate_credentials(provider_id, credentials, options=None):
    definition = provider(provider_id)
    allowed = {field["key"] for field in definition["fields"]}
    mode = validate_options(provider_id, options).get("auth_mode")
    active = [field for field in definition["fields"] if not field.get("auth_mode") or field["auth_mode"] == mode]
    required = {field["key"] for field in active if field["required"]}
    if not isinstance(credentials, dict) or not required.issubset(credentials) or set(credentials) - allowed:
        raise AliDNSError("InvalidCredentials")
    if any(not isinstance(value, str) or len(value) > 4096 for value in credentials.values()):
        raise AliDNSError("InvalidCredentials")
    inactive = allowed - {field["key"] for field in active}
    if any(credentials.get(key) for key in inactive) or any(not credentials.get(key, "").strip() for key in required):
        raise AliDNSError("InvalidCredentials")
    return definition["validate"](**credentials)
