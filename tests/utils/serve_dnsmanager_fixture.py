"""Disposable browser fixture: synthetic encrypted accounts, mocked cloud only."""

import os
from pathlib import Path
from uuid import uuid4

from flask import send_from_directory
from jinja2 import DictLoader

from test_dnsmanager import HTTPTests

assert os.environ.get("DNSMANAGER_BROWSER_FIXTURE") == "yes", "Fixture is opt-in"
HTTPTests.setUpClass()
fixture = HTTPTests()
fixture.setUp()
# A second, synthetic provider exercises schema-driven fields; never packaged.
from bw_dnsmanager.providers import PROVIDERS
import types

PROVIDERS["fixture"] = {
    "id": "fixture",
    "name": "Fixture Provider",
    "fields": [{"key": "api_token", "id": "fixture-token", "label": "API Token", "required": True}],
    "validate": lambda api_token: types.SimpleNamespace(api_token=api_token),
    "client": lambda credentials, domains: fixture.cloud,
}
fixture.cloud.list_records.side_effect = lambda domain, page, size: {
    "DomainRecords": {"Record": [{"RecordId": "123", "RR": "www", "Type": "A", "Value": "192.0.2.10", "TTL": 600, "Line": "default", "Status": "ENABLE"}]},
    "TotalCount": 1,
}
fixture.cloud._call.side_effect = lambda action, **values: {
    "DomainRecords": {
        "Record": (
            [{"RecordId": "123", "RR": "www", "Type": "A", "Value": "192.0.2.10", "TTL": 600, "Line": "default", "Status": "ENABLE"}]
            if values.get("RRKeyWord", "") in "www" and values.get("Type", "A") == "A"
            else []
        )
    },
    "TotalCount": 1 if values.get("RRKeyWord", "") in "www" and values.get("Type", "A") == "A" else 0,
}
fixture.cloud.allowed_domains = {"example.com"}
fixture.cloud.options = {"http_timeout": 10, "polling_interval": 1, "propagation_timeout": 3}
fixture.module.check_record = lambda *args: {
    "name": "www.example.com",
    "type": "A",
    "expected": "192.0.2.10",
    "answers": ["192.0.2.10"],
    "matched": True,
    "scope": "single_recursive_resolver",
}
fixture.cloud._domain.side_effect = lambda domain: domain
fixture.cloud.get_record.return_value = {
    "RecordId": "123",
    "DomainName": "example.com",
    "RR": "www",
    "Type": "A",
    "Value": "192.0.2.10",
    "TTL": 600,
    "Line": "default",
    "Status": "ENABLE",
}
fixture.store.save_account(
    str(uuid4()),
    "Second fixture",
    ["example.net", "sub.example.net"],
    {"access_key_id": "fixture-second-id", "access_key_secret": "fixture-second-secret"},
    0,
    "admin",
    str(uuid4()),
)
fixture.app.jinja_loader = DictLoader(
    {
        "dashboard.html": """<!doctype html><html lang="zh"><head><meta charset="utf-8"><link rel="stylesheet" href="/fixture-assets/css/core.css"><link rel="stylesheet" href="/fixture-assets/css/theme-default.css"></head><body><main class="container py-4">{% block content %}{% endblock %}</main>{% block scripts %}{% endblock %}</body></html>"""
    }
)


@fixture.app.route("/fixture-assets/<path:name>")
def asset(name):
    return send_from_directory(Path("/usr/share/bunkerweb/ui/app/static"), name)


fixture.app.run(host="0.0.0.0", port=7000, use_reloader=False)
