FROM alpine:3.6

RUN apk update && apk add ca-certificates

COPY cert-manage /bin/cert-manage
COPY main /bin/main
COPY whitelist.json /whitelist.json
