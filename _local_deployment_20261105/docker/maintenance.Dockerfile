# Runtime for the private account-maintenance API. It never runs Apache or
# the Phorge image's initialization entrypoint and has no Docker access.
ARG PHORGE_BASE_IMAGE=team-management/phorge:e5141c7
FROM ${PHORGE_BASE_IMAGE}
USER root
# The base image already pins Debian's package sources to the build snapshot.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 team-maintenance \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --home-dir /tmp --shell /usr/sbin/nologin team-maintenance
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /workspace
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["python3", "/workspace/config/maintenance/service.py"]
CMD []
