FROM golang:1.22-alpine AS build

WORKDIR /src

RUN apk add --no-cache git

COPY go.mod ./
COPY . .

RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/oob ./cmd/oob

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata docker-cli && adduser -D -u 10001 recon

WORKDIR /app
COPY --from=build /out/api /app/api
COPY --from=build /out/worker /app/worker
COPY --from=build /out/oob /app/oob

RUN mkdir -p /var/lib/recon/raw && chown -R recon:recon /var/lib/recon

USER recon
EXPOSE 8080

ENTRYPOINT ["/app/api"]
