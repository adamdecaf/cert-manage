FROM ubuntu:17.10

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl \
            chromium-browser \
            firefox libnss3 libnss3-tools libgtk-3-0 libdbus-glib-1-2 xvfb \
            openjdk-9-jdk ca-certificates-java && \
    rm -rf /var/lib/apt/lists/*

COPY cert-manage /bin/cert-manage
COPY whitelist.json /whitelist.json

COPY test.sh /test.sh
CMD ["/test.sh"]
