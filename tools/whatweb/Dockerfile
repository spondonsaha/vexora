FROM debian:bookworm-slim

# WhatWeb ships in Debian main; python3 runs the stdin/stdout JSON adapter.
RUN apt-get update \
    && apt-get install -y --no-install-recommends whatweb python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/whatweb
COPY whatweb_adapter.py /opt/whatweb/whatweb_adapter.py

ENTRYPOINT ["python3", "/opt/whatweb/whatweb_adapter.py"]
