ARG BASE_UI=ghcr.io/bunkerity/bunkerweb-ui@sha256:72b686b5cfdfa54ecc2e900a05b44303cc1be9323de58b481c49568f83d2e472
ARG BASE_SCHEDULER=ghcr.io/bunkerity/bunkerweb-scheduler@sha256:18cb223b19cc19083ad9e2ef3451a2fdc6efb485dc59fb51a2b0c8e4eb7e8a57
ARG BASE_WORKER=ghcr.io/bunkerity/bunkerweb@sha256:62bd2c76ec1f7a35e5a6b03ce39970ad770f8269f7f78cd6d8b7cdb2f3db49aa

FROM ${BASE_SCHEDULER} AS additions
USER root
ARG SOURCE_DATE_EPOCH
COPY wheelhouse /wheelhouse
COPY requirements-aliyun-overlay.txt /requirements.txt
RUN python -m pip install --no-cache-dir --no-compile --no-deps --no-build-isolation --require-hashes \
    --no-index --find-links=/wheelhouse --target /new-python -r /requirements.txt

FROM ${BASE_UI} AS ui
USER root
COPY --from=additions --chown=0:101 --chmod=550 /new-python/ /usr/share/bunkerweb/deps/python/
COPY --chown=0:101 --chmod=550 letsencrypt/ /usr/share/bunkerweb/core/letsencrypt/
COPY --chown=0:101 --chmod=550 alidns.py /usr/share/bunkerweb/utils/alidns.py
ARG SOURCE_REVISION
ARG SOURCE_TREE_SHA256
LABEL org.opencontainers.image.source="https://github.com/egerdy/bunkerweb" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.tianmu.bunkerweb.source-tree-sha256="${SOURCE_TREE_SHA256}" \
      io.tianmu.bunkerweb.base-version="1.6.17"
USER ui:ui

FROM ${BASE_SCHEDULER} AS scheduler
USER root
COPY --from=additions --chown=0:101 --chmod=550 /new-python/ /usr/share/bunkerweb/deps/python/
COPY --chown=0:101 --chmod=550 letsencrypt/ /usr/share/bunkerweb/core/letsencrypt/
ARG SOURCE_REVISION
ARG SOURCE_TREE_SHA256
LABEL org.opencontainers.image.source="https://github.com/egerdy/bunkerweb" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.tianmu.bunkerweb.source-tree-sha256="${SOURCE_TREE_SHA256}" \
      io.tianmu.bunkerweb.base-version="1.6.17"
USER scheduler:scheduler

FROM ${BASE_WORKER} AS worker
USER root
COPY --chown=0:101 --chmod=550 letsencrypt/ /usr/share/bunkerweb/core/letsencrypt/
COPY lkg/guard.py lkg/start.py lkg/patch_api.py /opt/bw-lkg/
COPY lkg/lkg_guard.lua /usr/share/bunkerweb/lua/bunkerweb/lkg_guard.lua
RUN python3 /opt/bw-lkg/patch_api.py \
    && chmod 755 /opt/bw-lkg/start.py \
    && mkdir /lkg && chown 101:101 /lkg && chmod 700 /lkg
ARG SOURCE_REVISION
ARG SOURCE_TREE_SHA256
LABEL org.opencontainers.image.source="https://github.com/egerdy/bunkerweb" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.tianmu.bunkerweb.source-tree-sha256="${SOURCE_TREE_SHA256}" \
      io.tianmu.bunkerweb.base-version="1.6.17" \
      io.tianmu.bunkerweb.lkg="enabled"
USER nginx
ENTRYPOINT ["/opt/bw-lkg/start.py"]
