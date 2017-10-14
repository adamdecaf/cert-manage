FROM ubuntu:17.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY cert-manage /bin/cert-manage
COPY main /bin/main
COPY whitelist.json /whitelist.json
