"""DNS pages and same-origin routes. No global hooks and no Nginx writes."""

from functools import wraps
from hashlib import sha256
from pathlib import Path

from flask import Blueprint, jsonify, make_response, render_template, request, url_for
from flask_login import current_user, login_required

from alidns import AliDNSError, record_fingerprint
from app.dependencies import DB
from bw_dnsmanager.store import Store
from bw_dnsmanager.providers import public_providers
from bw_dnsmanager.record_filters import list_records
from bw_dnsmanager.resolution import check_record

ROOT = Path(__file__).parent
dnsmanager = Blueprint(
    "dnsmanager",
    __name__,
    template_folder=str(ROOT / "templates"),
    static_folder=str(ROOT / "static"),
    static_url_path="/dnsmanager/static",
)


def route_guard(write=False, admin=False):
    def decorate(function):
        @wraps(function)
        @login_required
        def guarded(*args, **kwargs):
            if write and (DB.readonly or "write" not in current_user.list_permissions or (admin and not current_user.admin)):
                return jsonify(error="WriteForbidden"), 403
            if request.method == "POST" and (not request.is_json or request.content_length is None or request.content_length > 32768):
                return jsonify(error="InvalidRequestBody"), 400
            try:
                return function(Store(), *args, **kwargs)
            except AliDNSError as error:
                status = (
                    409
                    if error.code
                    in {
                        "RecordChanged",
                        "AccountChanged",
                        "DuplicateOperation",
                        "OperationInProgress",
                        "AccountHasUnresolvedOperations",
                    }
                    else 400
                )
                if error.code in {
                    "CredentialStoreNotConfigured",
                    "CredentialDecryptionFailed",
                    "UnsafeCredentialDirectory",
                    "UnsafeCredentialDatabase",
                }:
                    status = 503
                return (
                    jsonify(
                        error=error.code,
                        request_id=error.request_id,
                        outcome_unknown=error.outcome_unknown,
                    ),
                    status,
                )
            except Exception:
                # No traceback/request body: SDK exceptions may contain secrets.
                return (
                    jsonify(error="DNSManagerUnavailable", outcome_unknown=write),
                    503,
                )

        return guarded

    return decorate


def body():
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise AliDNSError("InvalidRequestBody")
    return value


def page_number():
    value = request.args.get("page", "1")
    if not value.isdecimal() or len(value) > 7 or not 1 <= int(value) <= 1_000_000:
        raise AliDNSError("InvalidPagination")
    return int(value)


@dnsmanager.route("/dnsmanager", methods=["GET"])
@login_required
def dnsmanager_page():
    # The host UI replaces Jinja's url_for with its *_page convention. Resolve
    # namespaced static URLs here using Flask's actual helper.
    response = make_response(
        render_template(
            "dnsmanager.html",
            can_write=not DB.readonly and "write" in current_user.list_permissions,
            can_admin=current_user.admin,
            dnsmanager_providers=public_providers(),
            dnsmanager_base=url_for("dnsmanager.dnsmanager_page"),
            dnsmanager_script=url_for(
                "dnsmanager.static",
                filename="dnsmanager.js",
                v=sha256((ROOT / "static/dnsmanager.js").read_bytes()).hexdigest()[:16],
            ),
        )
    )
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    return response


@dnsmanager.route("/dnsmanager/accounts", methods=["GET"])
@route_guard()
def accounts(store):
    return jsonify(accounts=store.accounts(masked=current_user.admin))


@dnsmanager.route("/dnsmanager/accounts/save", methods=["POST"])
@route_guard(write=True, admin=True)
def save_account(store):
    value = body()
    with store.mutation_lock(value.get("id")):
        store.save_account(
            value.get("id"),
            value.get("label"),
            value.get("domains"),
            value.get("credentials"),
            value.get("revision"),
            current_user.get_id(),
            value.get("operation_id"),
            value.get("provider_id"),
            value.get("options"),
        )
    return jsonify(saved=True)


@dnsmanager.route("/dnsmanager/accounts/delete", methods=["POST"])
@route_guard(write=True, admin=True)
def delete_account(store):
    value = body()
    with store.mutation_lock(value.get("id")):
        store.delete_account(
            value.get("id"),
            value.get("revision"),
            current_user.get_id(),
            value.get("operation_id"),
        )
    return jsonify(deleted=True)


@dnsmanager.route("/dnsmanager/domains", methods=["GET"])
@route_guard()
def domains(store):
    client = store.account(request.args.get("account", ""))
    # Configured scope, not a second local DNS record database. Records are read
    # live from AliDNS; listing configured zones also works with least-privilege RAM.
    return jsonify(domains=sorted(client.allowed_domains))


@dnsmanager.route("/dnsmanager/records", methods=["GET"])
@route_guard()
def records(store):
    client = store.account(request.args.get("account", ""))
    domain = client._domain(request.args.get("domain", ""))
    payload = list_records(client, domain, page_number(), 50, request.args.get("rr", "").strip(), request.args.get("type", "").upper())
    items = payload.get("DomainRecords", {}).get("Record", [])
    return jsonify(
        records=[
            {
                **record,
                "DomainName": domain,
                "fingerprint": record_fingerprint({**record, "DomainName": domain}),
            }
            for record in items
        ],
        total=payload.get("TotalCount", 0),
        page=page_number(),
    )


@dnsmanager.route("/dnsmanager/accounts/test", methods=["GET"])
@route_guard()
def test_connection(store):
    client = store.account(request.args.get("account", ""))
    domain = min(client.allowed_domains)
    client.list_records(domain, 1, 1)
    return jsonify(connected=True, domain=domain)


@dnsmanager.route("/dnsmanager/records/test", methods=["GET"])
@route_guard()
def test_resolution(store):
    client = store.account(request.args.get("account", ""))
    domain = client._domain(request.args.get("domain", ""))
    remaining = request.args.get("remaining", "60")
    if not remaining.isdecimal() or not 1 <= int(remaining) <= 600:
        raise AliDNSError("InvalidResolutionTimeout")
    return jsonify(check_record(client, domain, request.args.get("record_id", ""), int(remaining)))


@dnsmanager.route("/dnsmanager/records/write", methods=["POST"])
@route_guard(write=True)
def write_record(store):
    value = body()
    with store.mutation_lock(value.get("account")):
        return perform_write(store, value)


def perform_write(store, value):
    if value.get("confirmed") is not True:
        raise AliDNSError("ConfirmationRequired")
    action = value.get("action")
    if action not in {"add", "update", "delete", "status"}:
        raise AliDNSError("UnsupportedAction")
    account_id, operation_id = value.get("account"), value.get("operation_id")
    client = store.account(account_id)
    domain, record_id = value.get("domain"), value.get("record_id")
    domain = client._domain(domain)
    before = None if action == "add" else client.get_record(domain, record_id)
    raw_values = value.get("values")
    if action == "add" and isinstance(raw_values, dict):
        options = store.options(account_id, next(p["provider_id"] for p in store.accounts() if p["id"] == account_id))
        raw_values = {"TTL": options.get("ttl", 600), "Line": options.get("line", "default"), **raw_values}
    values = client._record_values(raw_values) if action in {"add", "update"} else None
    status = value.get("status") if action == "status" else None
    if action == "status" and status not in {"ENABLE", "DISABLE"}:
        raise AliDNSError("InvalidStatus")
    # Store the intent before contacting the write API. A process crash leaves a
    # durable PENDING operation that must be investigated, never replayed silently.
    store.begin(
        operation_id,
        current_user.get_id(),
        account_id,
        "record." + action,
        {
            "domain": domain,
            "record_id": record_id,
            "before": before,
            "after": values,
            "status": status,
        },
    )
    try:
        fingerprint = value.get("fingerprint")
        if action == "add":
            result = client.add_record(domain, values)
        elif action == "update":
            result = client.update_record(domain, record_id, values, fingerprint)
        elif action == "delete":
            result = client.delete_record(domain, record_id, fingerprint)
        else:
            result = client.set_record_status(domain, record_id, status, fingerprint)
    except AliDNSError as error:
        store.finish(
            operation_id,
            "UNKNOWN" if error.outcome_unknown else "REJECTED",
            {"error": error.code, "request_id": error.request_id},
        )
        raise
    except Exception:
        store.finish(operation_id, "UNKNOWN", {"error": "UnexpectedFailure"})
        raise AliDNSError("WriteOutcomeUnknown", outcome_unknown=True) from None
    try:
        store.finish(operation_id, "SUCCEEDED", result)
    except Exception:
        raise AliDNSError("WriteOutcomeUnknown", outcome_unknown=True) from None
    return jsonify(result=result, operation_id=operation_id)


@dnsmanager.route("/dnsmanager/audit", methods=["GET"])
@route_guard()
def audit(store):
    return jsonify(events=store.audit(page_number()), page=page_number())
