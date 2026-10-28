FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl openjdk-21-jdk-headless && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sfn "$(dirname "$(dirname "$(readlink -f "$(which javac)")")")" /usr/lib/jvm/java-home
ENV JAVA_HOME=/usr/lib/jvm/java-home
ENV PATH="${JAVA_HOME}/bin:${PATH}"

COPY cert-manage /bin/cert-manage
RUN chmod +x /bin/cert-manage
COPY globalsign-whitelist.json /whitelist.json
COPY us-whitelist.yaml /whitelist.yaml

COPY Download.java /Download.java
RUN javac /Download.java

COPY localcert.pem /localcert.pem

COPY script.sh /bin/script.sh
RUN chmod +x /bin/script.sh
CMD /bin/script.sh
