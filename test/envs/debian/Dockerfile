FROM debian:9

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates \
    openjdk-8-jdk ca-certificates-java && \
    rm -rf /var/lib/apt/lists/*

COPY cert-manage-linux-amd64 /bin/cert-manage
COPY globalsign-whitelist.json /whitelist.json

COPY Download.java /Download.java
RUN cd / && javac Download.java
