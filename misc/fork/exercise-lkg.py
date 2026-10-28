#!/usr/bin/env python3
"""Destructive fault injection ONLY against the dedicated bw-fork-lkg Compose project."""

import hashlib
import http.client
import io
import json
import pathlib
import socket
import ssl
import subprocess
import tarfile
import time
import uuid

RESULTS = []
CONTAINER = "bw-fork-lkg-w1-1"


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, check=check)


def compose(*args):
    return command("docker", "compose", "-f", "compose.json", *args)


def mark():
    try:
        c = http.client.HTTPConnection("127.0.0.1", 19680, timeout=3)
        c.request("GET", "/version-marker", headers={"Host": "lkg.example.test"})
        r = c.getresponse()
        value = r.read().decode()
        c.close()
        return value if r.status == 200 else str(r.status)
    except (OSError, http.client.HTTPException):
        return "offline"


def fingerprint():
    try:
        with socket.create_connection(("127.0.0.1", 19643), timeout=3) as s:
            with ssl._create_unverified_context().wrap_socket(s, server_hostname="lkg.example.test") as t:
                return hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()
    except OSError:
        return None


def status():
    r = command("docker", "exec", CONTAINER, "python3", "/opt/bw-lkg/guard.py", "status")
    return json.loads(r.stdout)


def nginx_ok():
    return command("docker", "exec", CONTAINER, "nginx", "-t", check=False).returncode == 0


def wait_for(predicate, seconds=120):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            if predicate():
                return True
        except (OSError, subprocess.CalledProcessError, ValueError):
            pass
        time.sleep(0.5)
    return False


def record(name, passed, **details):
    item = {"test": name, "passed": bool(passed)} | details
    RESULTS.append(item)
    pathlib.Path("lkg-results.json").write_text(json.dumps(RESULTS, indent=2))
    print(json.dumps(item), flush=True)
    if not passed:
        raise AssertionError(name)


def archive(root):
    return command("docker", "exec", CONTAINER, "tar", "-czf", "-", "-C", root, ".").stdout


def edit_archive(data, version=None, invalid=False, broken_cert=False):
    output = io.BytesIO()
    changed = False
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as src:
        with tarfile.open(fileobj=output, mode="w:gz") as dst:
            for item in src:
                content = src.extractfile(item).read() if item.isfile() else None
                if version and item.name.endswith("marker.conf"):
                    content = content.replace(b'"v1"', ('"' + version + '"').encode())
                    item.size = len(content)
                    changed = True
                if broken_cert and "customcert/lkg.example.test/key.pem" in item.name:
                    content = b"intentionally invalid test key\n"
                    item.size = len(content)
                    changed = True
                dst.addfile(item, io.BytesIO(content) if content is not None else None)
            if invalid:
                item = tarfile.TarInfo("server-http/lkg.example.test/rejected.conf")
                content = b"this_directive_does_not_exist on;\n"
                item.size = len(content)
                item.mode = 0o644
                dst.addfile(item, io.BytesIO(content))
                changed = True
    if not changed:
        raise AssertionError("Expected test file absent from archive")
    return output.getvalue()


def api(path, content=None):
    c = http.client.HTTPConnection("127.0.0.1", 19500, timeout=90)
    headers = {"Host": "bwapi"}
    if content is not None:
        boundary = "bw-fork-lkg-" + uuid.uuid4().hex
        body = (
            "--" + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="candidate.tar.gz"' "\r\nContent-Type: application/gzip\r\n\r\n"
        ).encode()
        body += content + ("\r\n--" + boundary + "--\r\n").encode()
        headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
    else:
        body = b""
    c.request("POST", path, body, headers)
    r = c.getresponse()
    r.read()
    code = r.status
    c.close()
    return code


def recreate():
    compose("up", "-d", "--no-deps", "--force-recreate", "--pull", "never", "w1")


def main():
    if json.loads(compose("config", "--format", "json").stdout)["name"] != "bw-fork-lkg":
        raise SystemExit("Refusing to run outside the dedicated bw-fork-lkg project")
    expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pathlib.Path("certs/cert.pem").read_text())).hexdigest()
    record("initial_business_lkg_and_certificate", wait_for(lambda: mark() == "v1" and fingerprint() == expected and not status()["pending"]))
    compose("stop", "scheduler")
    baseline = archive("/etc/bunkerweb/configs")
    generation = status()["index"]["generations"][0]["id"]
    assert api("/custom_configs", edit_archive(baseline, invalid=True)) == 200
    code = api("/reload?test=no")  # The native no-test switch must not bypass the guard.
    record("invalid_candidate_rejected_even_test_no", code >= 400 and mark() == "v1" and nginx_ok(), api_status=code, active=mark())
    record("rejected_candidate_not_promoted", status()["index"]["generations"][0]["id"] == generation)
    recreate()
    record("recreate_without_scheduler_restores_lkg", wait_for(lambda: mark() == "v1" and fingerprint() == expected and nginx_ok()))
    assert api("/custom_configs", edit_archive(baseline, version="v2")) == 200
    command("docker", "kill", "--signal", "KILL", CONTAINER)
    recreate()
    record("crash_during_uncommitted_push_restores_lkg", wait_for(lambda: mark() == "v1" and fingerprint() == expected and nginx_ok()))
    assert api("/cache", edit_archive(archive("/var/cache/bunkerweb"), broken_cert=True)) == 200
    code = api("/reload?test=yes")
    record("dynamic_certificate_mismatch_rejected_and_restored", code >= 400 and fingerprint() == expected and mark() == "v1" and nginx_ok(), api_status=code)
    assert api("/custom_configs", edit_archive(baseline, version="v2")) == 200
    code = api("/reload?test=yes")
    record("valid_v2_promoted_after_reload", code == 200 and mark() == "v2" and not status()["pending"], api_status=code)
    recreate()
    record("v2_and_certificate_survive_recreate", wait_for(lambda: mark() == "v2" and fingerprint() == expected and nginx_ok()))
    # Corrupt only this project's newest private snapshot. The previous committed generation remains.
    current = status()["index"]["generations"][0]["archive"]
    command("docker", "exec", CONTAINER, "python3", "-c", "import pathlib; pathlib.Path('/lkg/' + " + repr(current) + ").write_bytes(b'corrupt-test')")
    recreate()
    record("corrupt_newest_snapshot_falls_back_to_previous", wait_for(lambda: mark() == "v1" and fingerprint() == expected and nginx_ok()))
    current = status()["index"]["generations"][0]["archive"]
    command(
        "docker",
        "exec",
        CONTAINER,
        "python3",
        "-c",
        "import pathlib,shutil; p=pathlib.Path('/lkg/' + " + repr(current) + "); shutil.copy2(p,'/lkg/test-backup'); p.write_bytes(b'corrupt-all-test')",
    )
    recreate()
    stopped = wait_for(lambda: json.loads(command("docker", "inspect", CONTAINER).stdout)[0]["State"]["Status"] == "exited", seconds=20)
    record("no_intact_snapshot_refuses_startup", stopped and mark() == "offline")
    command(
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        "bw-fork-lkg_lkg1:/lkg",
        "--entrypoint",
        "python3",
        json.loads(compose("config", "--format", "json").stdout)["services"]["w1"]["image"],
        "-c",
        "import shutil,pathlib; shutil.copy2('/lkg/test-backup','/lkg/' + " + repr(current) + "); pathlib.Path('/lkg/test-backup').unlink()",
    )
    recreate()
    record("restored_snapshot_recovers_service", wait_for(lambda: mark() == "v1" and fingerprint() == expected and nginx_ok()))
    print("ALL_LKG_TESTS_PASSED", flush=True)


if __name__ == "__main__":
    main()
