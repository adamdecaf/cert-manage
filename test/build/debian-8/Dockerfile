FROM debian:8

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY cert-manage /bin/cert-manage
COPY whitelist.json /whitelist.json

COPY test.sh /test.sh
CMD ["/test.sh"]
