FROM alpine:3.20
RUN apk add --no-cache curl jq
COPY ct.sh /usr/local/bin/ct
RUN chmod +x /usr/local/bin/ct
ENTRYPOINT ["ct"]
