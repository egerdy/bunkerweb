#!/bin/sh
# Run on the Docker build host from a checkout/snapshot; does not alter services.
set -eu

FORK_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
SCHEDULER_BASE=${SCHEDULER_BASE:-ghcr.io/bunkerity/bunkerweb-scheduler@sha256:18cb223b19cc19083ad9e2ef3451a2fdc6efb485dc59fb51a2b0c8e4eb7e8a57}

docker run --rm --name bunkerweb-fork-compat \
    --memory=384m --memory-swap=384m --cpus=1 --pids-limit=128 \
    --read-only --user=101:101 --tmpfs /tmp:rw,uid=101,gid=101,size=256m \
    -v "$FORK_ROOT:/workspace:ro" -w /workspace \
    -e PYTHONPATH=/tmp/aliyun:/usr/share/bunkerweb/deps/python:/usr/share/bunkerweb/db:/usr/share/bunkerweb/utils \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    --entrypoint /bin/sh "$SCHEDULER_BASE" -c '
set -eu
python -B -m pip install --no-cache-dir --no-deps --no-build-isolation --require-hashes \
    --no-index --find-links=/workspace/misc/fork/wheelhouse \
    --target /tmp/aliyun -r misc/fork/requirements-aliyun-overlay.txt
python -B -m unittest discover -s tests/utils -p "test_ali*.py" -v
'
