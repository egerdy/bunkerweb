"""Read-only checks against a fixed public recursive resolver, not global DNS proof."""

import ipaddress
import json
import requests
from alidns import AliDNSError, record_fingerprint

TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16}


def canonical(kind, value):
    if kind in {"A", "AAAA"}:
        return str(ipaddress.ip_address(value))
    if kind == "CNAME":
        return value.rstrip(".").lower()
    if kind == "TXT" and value.startswith('"'):
        # JSON resolver renders TXT RDATA as one or more quoted strings.
        decoder = json.JSONDecoder()
        pieces = []
        rest = value.strip()
        while rest:
            piece, end = decoder.raw_decode(rest)
            if not isinstance(piece, str):
                raise ValueError()
            pieces.append(piece)
            rest = rest[end:].strip()
        return "".join(pieces)
    return value


def check_record(client, domain, record_id, timeout=None):
    record = client.get_record(domain, record_id)
    kind = record.get("Type")
    if kind not in TYPES or "*" in record.get("RR", ""):
        raise AliDNSError("UnsupportedResolutionTest")
    options = client.options
    rr = record["RR"]
    name = domain if rr == "@" else rr + "." + domain
    # No user-supplied endpoint, no credentials in this request. A result covers
    # this recursive resolver only, not all authoritative/ISP caches.
    budget = min(options["http_timeout"], timeout or options["http_timeout"])
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(
                "https://dns.alidns.com/resolve", params={"name": name, "type": kind}, timeout=(min(5, budget / 2), budget / 2), allow_redirects=False
            )
            if response.status_code != 200 or len(response.content) > 65536:
                raise ValueError()
            payload = response.json()
        if not isinstance(payload, dict) or type(payload.get("Status")) is not int:
            raise ValueError()
        answers = [
            row["data"]
            for row in payload.get("Answer", [])
            if isinstance(row, dict)
            and row.get("type") == TYPES[kind]
            and row.get("name", "").rstrip(".").lower() == name.lower()
            and isinstance(row.get("data"), str)
        ]
        expected = record["Value"] if kind == "TXT" else canonical(kind, record["Value"])
        matched = record.get("Status") == "ENABLE" and payload["Status"] == 0 and any(canonical(kind, data) == expected for data in answers)
        return {
            "name": name,
            "type": kind,
            "expected": record["Value"],
            "answers": answers,
            "matched": matched,
            "rcode": payload["Status"],
            "resolver": "AliDNS public recursive (DoH)",
            "scope": "single_recursive_resolver",
            "record_fingerprint": record_fingerprint(record),
        }
    except (requests.RequestException, ValueError, TypeError, KeyError):
        raise AliDNSError("ResolutionLookupFailed") from None
