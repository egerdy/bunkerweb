"""Create a fresh, dedicated two-component LKG fault fixture on 100.2."""

import argparse
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("destination", type=Path)
parser.add_argument("--release-manifest", required=True, type=Path)
args = parser.parse_args()
assert not args.destination.exists(), "Use a fresh directory and volumes"
manifest = json.loads(args.release_manifest.read_text())
images = {item["component"]: item["image"].rsplit(":", 1)[0] + "@" + item["digest"] for item in manifest["images"]}
args.destination.mkdir(parents=True)
certs = args.destination / "certs"
certs.mkdir()
subprocess.run(
    [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=lkg.example.test",
        "-keyout",
        str(certs / "key.pem"),
        "-out",
        str(certs / "cert.pem"),
    ],
    check=True,
    capture_output=True,
)
# Mock certificate only; UID101 Scheduler needs to read the fixture.
(certs / "key.pem").chmod(0o644)
common = {
    "restart": "no",
    "cpus": 0.5,
    "mem_limit": "384m",
    "memswap_limit": "384m",
    "networks": ["lab"],
    "pull_policy": "never",
    "logging": {"driver": "json-file", "options": {"max-size": "5m", "max-file": "2"}},
}
env = {"API_WHITELIST_IP": "127.0.0.0/8 100.64.6.0/24", "WORKER_PROCESSES": "1"}
worker = common | {
    "image": images["worker"],
    "environment": env,
    "volumes": ["lkg1:/lkg"],
    "ports": ["127.0.0.1:19680:8080", "127.0.0.1:19643:8443", "127.0.0.1:19500:5000"],
}
scheduler_env = env | {
    "BUNKERWEB_INSTANCES": "w1",
    "MULTISITE": "yes",
    "SERVER_NAME": "lkg.example.test",
    "SCHEDULER_MAX_WORKERS": "1",
    "USE_MODSECURITY": "no",
    "USE_REVERSE_PROXY": "no",
    "AUTO_REDIRECT_HTTP_TO_HTTPS": "no",
    "USE_CUSTOM_SSL": "yes",
    "CUSTOM_SSL_CERT": "/certs/cert.pem",
    "CUSTOM_SSL_KEY": "/certs/key.pem",
    "USE_BLACKLIST": "no",
    "USE_DNSBL": "no",
    "USE_BUNKERNET": "no",
    "SEND_ANONYMOUS_REPORT": "no",
    "USE_LIMIT_REQ": "no",
    "USE_LIMIT_CONN": "no",
    "USE_BAD_BEHAVIOR": "no",
    "lkg.example.test_CUSTOM_CONF_SERVER_HTTP_marker": 'location = /version-marker { return 200 "v1"; }',
    "RELOAD_MIN_TIMEOUT": "60",
    "SEND_FILES_MIN_TIMEOUT": "60",
}
scheduler = common | {"image": images["scheduler"], "environment": scheduler_env, "volumes": ["storage:/data", "./certs:/certs:ro"], "depends_on": ["w1"]}
value = {
    "name": "bw-fork-lkg",
    "services": {"w1": worker, "scheduler": scheduler},
    "volumes": {"lkg1": {}, "storage": {}},
    "networks": {"lab": {"ipam": {"config": [{"subnet": "100.64.6.0/24"}]}}},
}
(args.destination / "compose.json").write_text(json.dumps(value, indent=2) + "\n")
print(json.dumps({"lab_created": str(args.destination), "project": value["name"]}))
