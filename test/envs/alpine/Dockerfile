FROM alpine:3.7

RUN apk update && apk add ca-certificates openjdk8 java-cacerts

COPY Download.java /Download.java
ENV JAVA_HOME /usr/lib/jvm/java-1.8-openjdk
RUN cd / && /usr/lib/jvm/java-1.8-openjdk/bin/javac /Download.java

COPY globalsign-whitelist.json /whitelist.json
COPY cert-manage-linux-amd64 /bin/cert-manage
