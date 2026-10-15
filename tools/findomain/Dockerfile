FROM debian:bookworm-slim AS fetch
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && rm -rf /var/lib/apt/lists/*
ARG FINDOMAIN_VERSION=9.0.4
RUN curl -fsSL "https://github.com/findomain/findomain/releases/download/${FINDOMAIN_VERSION}/findomain-linux.zip" -o /tmp/findomain.zip \
 && unzip /tmp/findomain.zip -d /usr/local/bin \
 && chmod +x /usr/local/bin/findomain

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /usr/local/bin/findomain /usr/local/bin/findomain
ENTRYPOINT ["findomain"]
