#!/usr/bin/env python3
"""Worker-local preflight and durable last-known-good configuration.

Called while the upstream API swap lock is held. Snapshots contain secrets:
the /lkg volume and every archive/index are private to UID 101.
"""

import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import uuid

STATE = pathlib.Path(os.environ.get("BW_LKG_DIR", "/lkg"))
NGINX = "/usr/sbin/nginx"
ROOTS = {
    "nginx": pathlib.Path("/etc/nginx"),
    "cache": pathlib.Path("/data/cache"),
    "configs": pathlib.Path("/data/configs"),
    "plugins": pathlib.Path("/data/plugins"),
    "pro_plugins": pathlib.Path("/etc/bunkerweb/pro/plugins"),
    "www": pathlib.Path("/data/www"),
}


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    fd, name = tempfile.mkstemp(prefix=".write-", dir=STATE)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        sync_dir(STATE)
    finally:
        pathlib.Path(name).unlink(missing_ok=True)


def event(action, **fields):
    atomic_json(STATE / "last-event.json", {"action": action, "time": time.time()} | fields)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_certificates(cache):
    # Lua-loaded certificates are not necessarily read by nginx -t. Certbot's
    # live/cert.pem and live/fullchain.pem both use live/privkey.pem, unlike
    # customcert/selfsigned's cert.pem + key.pem convention.
    key_names = {"cert.pem": "key.pem", "fullchain.pem": "privkey.pem", "default-server-cert.pem": "default-server-cert.key"}
    for cert in cache.rglob("*.pem"):
        if cert.name not in key_names or not any(p in {"customcert", "selfsigned", "letsencrypt", "misc"} for p in cert.parts):
            continue
        key_name = "privkey.pem" if cert.name == "cert.pem" and "letsencrypt" in cert.parts else key_names[cert.name]
        key = cert.with_name(key_name)
        pub_cert = subprocess.run(["/usr/bin/openssl", "x509", "-pubkey", "-noout", "-in", str(cert)], capture_output=True, timeout=5)
        pub_key = subprocess.run(["/usr/bin/openssl", "pkey", "-pubout", "-in", str(key)], capture_output=True, timeout=5)
        if pub_cert.returncode or pub_key.returncode or pub_cert.stdout != pub_key.stdout:
            raise RuntimeError("certificate/key pair preflight failed")


def check():
    check_certificates(pathlib.Path("/data/cache"))
    r = subprocess.run([NGINX, "-t"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if r.returncode:
        # Private evidence; never include config/certificate errors in public API responses.
        p = STATE / "last-preflight-error.log"
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(r.stdout)
        raise RuntimeError("nginx preflight failed")


def read_index():
    p = STATE / "index.json"
    return json.loads(p.read_text()) if p.exists() else {"generations": []}


def snapshot():
    generation = uuid.uuid4().hex
    temporary = STATE / (".snapshot-" + generation)
    target = STATE / (generation + ".tar")
    try:
        with temporary.open("xb") as raw:
            os.chmod(temporary, 0o600)
            with tarfile.open(fileobj=raw, mode="w") as archive:
                for name, path in ROOTS.items():
                    if path.is_dir():
                        archive.add(
                            path, arcname=name, filter=lambda item: None if any(p.startswith(".bw-") for p in pathlib.PurePosixPath(item.name).parts) else item
                        )
            raw.flush()
            os.fsync(raw.fileno())
        sha = digest(temporary)
        os.replace(temporary, target)
        sync_dir(STATE)
        return {"id": generation, "archive": target.name, "sha256": sha, "version": "1.6.17", "created_at": time.time()}
    finally:
        temporary.unlink(missing_ok=True)


def promote():
    item = snapshot()
    previous = read_index()["generations"]
    atomic_json(STATE / "index.json", {"generations": [item, *previous[:1]]})
    (STATE / "pending.json").unlink(missing_ok=True)
    sync_dir(STATE)
    # Index is durable before old archives are deleted. A crash can only leak an archive.
    keep = {x["archive"] for x in read_index()["generations"]}
    for archive in STATE.glob("*.tar"):
        if archive.name not in keep:
            archive.unlink()
    event("committed", generation=item["id"])


def remove(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def copy_tree(source, destination):
    """Reconcile inside owned roots; /etc's root ownership prevents root-dir rename."""
    destination.mkdir(parents=True, exist_ok=True)
    expected = {p.name for p in source.iterdir()}
    for p in list(destination.iterdir()):
        if p.name not in expected:
            remove(p)
    for src in source.iterdir():
        dst = destination / src.name
        if src.is_dir() and not src.is_symlink():
            if dst.is_symlink() or dst.is_file():
                remove(dst)
            copy_tree(src, dst)
        else:
            if dst.is_dir() and not dst.is_symlink():
                remove(dst)
            temp = destination / (".restore-" + uuid.uuid4().hex)
            if src.is_symlink():
                temp.symlink_to(os.readlink(src))
            else:
                shutil.copy2(src, temp)
                with temp.open("rb") as f:
                    os.fsync(f.fileno())
            os.replace(temp, dst)
    sync_dir(destination)


def clear_push_digests():
    for p in pathlib.Path("/var/tmp/bunkerweb/pushswap").glob("*.applied"):
        p.unlink()
    pathlib.Path("/var/tmp/bunkerweb_needs_config").touch()


def restore():
    index = read_index()
    if not index["generations"]:
        raise RuntimeError("no committed LKG")
    failures = []
    for item in index["generations"]:
        archive_path = STATE / item["archive"]
        if archive_path.parent != STATE or item.get("version") != "1.6.17" or not archive_path.is_file() or digest(archive_path) != item["sha256"]:
            failures.append(item["id"])
            continue
        # The data filter rejects archive traversal and escaping links, even for our own snapshots.
        with tempfile.TemporaryDirectory(prefix=".restore-", dir=STATE) as temp:
            stage = pathlib.Path(temp)
            with tarfile.open(archive_path) as archive:
                archive.extractall(stage, filter="data")
            for name, destination in ROOTS.items():
                src = stage / name
                if src.is_dir():
                    copy_tree(src, destination)
            check()
        clear_push_digests()
        if failures:
            atomic_json(STATE / "index.json", {"generations": [item]})
        (STATE / "pending.json").unlink(missing_ok=True)
        sync_dir(STATE)
        event("restored", generation=item["id"], rejected_snapshots=failures)
        return
    raise RuntimeError("no intact LKG snapshot; refusing startup")


def begin():
    if not read_index()["generations"]:
        check()
        promote()  # Initial loading configuration; first successful reload promotes business config.
    if not (STATE / "pending.json").exists():
        atomic_json(STATE / "pending.json", {"started_at": time.time()})


def preflight():
    try:
        check()
    except Exception:
        restore()
        event("rejected_and_restored")
        raise


def commit():
    deadline = time.monotonic() + 20
    while pathlib.Path("/var/tmp/bunkerweb/reloading").exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("new worker generation did not acknowledge reload")
        time.sleep(0.1)
    check()
    health = subprocess.run(["/usr/share/bunkerweb/helpers/healthcheck.sh", "ok"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    if health.returncode:
        raise RuntimeError("new worker generation is unhealthy")
    promote()


def boot():
    if not (STATE / "index.json").exists():
        return
    restore()
    # Upstream entrypoint requires this file even with KEEP_CONFIG_ON_RESTART=yes.
    shutil.copyfile("/etc/nginx/variables.env", "/tmp/variables.env")


def main():
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    with (STATE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        action = sys.argv[1]
        try:
            if action == "status":
                print(json.dumps({"index": read_index(), "pending": (STATE / "pending.json").exists()}))
            elif action == "begin":
                begin()
            elif action == "preflight":
                preflight()
            elif action == "commit":
                try:
                    commit()
                except Exception:
                    restore()
                    subprocess.run([NGINX, "-s", "reload"], capture_output=True, timeout=5)
                    raise
            elif action == "abort":
                restore()
            elif action == "boot":
                boot()
            else:
                raise RuntimeError("unknown guard action")
        except Exception as exc:
            with (STATE / "last-internal-error.log").open("w") as error:
                error.write(traceback.format_exc())
            # Exception type only: errors may contain certificate paths or private config values.
            print("LKG " + action + " failed: " + type(exc).__name__, file=sys.stderr)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
