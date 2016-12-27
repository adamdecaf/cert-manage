FROM alpine:3.5

RUN apk update && apk add ca-certificates

COPY cert-manage /bin/cert-manage

ENTRYPOINT ["/bin/cert-manage"]
