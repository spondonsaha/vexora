FROM debian:bookworm-slim

# WPScan is distributed as a Ruby gem; ruby-dev + build-essential compile its
# native dependencies (typhoeus/libcurl, nokogiri). python3 runs the adapter.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ruby ruby-dev build-essential pkg-config git \
        zlib1g-dev libcurl4-openssl-dev libxml2-dev libxslt1-dev libssl-dev \
        python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN gem install wpscan --no-document

WORKDIR /opt/wpscan
COPY wpscan_adapter.py /opt/wpscan/wpscan_adapter.py

ENTRYPOINT ["python3", "/opt/wpscan/wpscan_adapter.py"]
