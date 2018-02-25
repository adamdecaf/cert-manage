FROM ubuntu:17.10

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl \
            chromium-browser \
            firefox libnss3 libnss3-tools libgtk-3-0 libdbus-glib-1-2 xvfb \
            openjdk-9-jdk ca-certificates-java && \
    rm -rf /var/lib/apt/lists/*

COPY cert-manage-linux-amd64 /bin/cert-manage
COPY globalsign-whitelist.json /whitelist.json
COPY us-whitelist.yaml /whitelist.yaml

COPY Download.java /Download.java
RUN cd / && javac Download.java

COPY localcert.pem /localcert.pem

COPY script.sh /bin/script.sh
RUN chmod +x /bin/script.sh
CMD /bin/script.sh
