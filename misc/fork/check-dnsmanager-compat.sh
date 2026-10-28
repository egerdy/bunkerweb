#!/bin/sh
# Flask/crypto/SQLite compatibility in the pinned UI image; no service replacement.
set -eu
FORK_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
UI_BASE=${UI_BASE:-ghcr.io/bunkerity/bunkerweb-ui@sha256:72b686b5cfdfa54ecc2e900a05b44303cc1be9323de58b481c49568f83d2e472}
docker run --rm --name bunkerweb-dnsmanager-compat \
    --memory=384m --memory-swap=384m --cpus=1 --pids-limit=128 \
    --read-only --user=101:101 --tmpfs /tmp:rw,uid=101,gid=101,size=256m \
    -v "$FORK_ROOT:/workspace:ro" -w /workspace \
    -e PYTHONPATH=/tmp/aliyun:/usr/share/bunkerweb/deps/python:/usr/share/bunkerweb/db:/usr/share/bunkerweb/utils \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    --entrypoint /bin/sh "$UI_BASE" -c '
set -eu
python -B -m pip install --no-cache-dir --no-deps --no-build-isolation --require-hashes \
    --no-index --find-links=/workspace/misc/fork/wheelhouse \
    --target /tmp/aliyun -r misc/fork/requirements-aliyun-overlay.txt
python -B -m unittest discover -s tests/utils -p "test_dnsmanager*.py" -v
'
