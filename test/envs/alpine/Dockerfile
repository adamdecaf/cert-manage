FROM alpine:3.7

RUN apk update && apk add ca-certificates

COPY cert-manage-linux-amd64 /bin/cert-manage
COPY globalsign-whitelist.json /whitelist.json
