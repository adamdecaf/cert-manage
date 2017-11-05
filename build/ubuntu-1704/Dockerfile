FROM ubuntu:17.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl \
            chromium-browser \
            firefox libnss3 libnss3-tools libgtk-3-0 libdbus-glib-1-2 xvfb \
            openjdk-8-jdk ca-certificates-java && \
    rm -rf /var/lib/apt/lists/*

COPY cert-manage /bin/cert-manage
COPY main /bin/main
COPY whitelist.json /whitelist.json
