FROM alpine:3.6

RUN apk update && apk add ca-certificates

COPY cert-manage /bin/cert-manage
COPY whitelist.json /whitelist.json

COPY test.sh /test.sh
CMD ["/test.sh"]
