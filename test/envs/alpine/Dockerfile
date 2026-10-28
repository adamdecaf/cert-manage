FROM alpine:3.21

RUN apk add --no-cache ca-certificates curl openjdk21-jdk
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

COPY Download.java /Download.java
RUN javac /Download.java

COPY globalsign-whitelist.json /whitelist.json
COPY us-whitelist.yaml /whitelist.yaml
COPY cert-manage /bin/cert-manage
RUN chmod +x /bin/cert-manage

COPY localcert.pem /localcert.pem

COPY script.sh /bin/script.sh
RUN chmod +x /bin/script.sh
CMD /bin/script.sh
