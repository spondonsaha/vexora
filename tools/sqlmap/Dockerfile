FROM python:3.12-slim

# sqlmap ships its tamper scripts / payload XML next to the entrypoint, so we
# clone the upstream repository rather than rely on the PyPI console script.
# ca-certificates + git are build deps only; sqlmap itself is pure Python.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

WORKDIR /opt/sqlmap
ENTRYPOINT ["python3", "sqlmap.py"]
CMD ["-hh"]
