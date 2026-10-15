FROM golang:1.22-alpine AS build
RUN apk add --no-cache git
RUN git clone --depth 1 https://github.com/tomnomnom/assetfinder /src
# assetfinder's Cert Spotter source targets the retired v0 API
# (certspotter.com/api/v0/certs -> HTTP 410 Gone). Point it at the current v1
# issuances API so the source works again. crt.sh (its other source) is
# frequently down; every source error is non-fatal.
RUN sed -i 's#https://certspotter.com/api/v0/certs?domain=%s#https://api.certspotter.com/v1/issuances?domain=%s\&include_subdomains=true\&expand=dns_names#' /src/certspotter.go
WORKDIR /src
RUN go mod init assetfinder && CGO_ENABLED=0 go build -o /assetfinder .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /assetfinder /usr/local/bin/assetfinder
ENTRYPOINT ["assetfinder"]
