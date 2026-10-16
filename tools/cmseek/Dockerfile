FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK /opt/CMSeeK \
    && pip install --no-cache-dir -r /opt/CMSeeK/requirements.txt

WORKDIR /opt/CMSeeK
COPY cmseek_adapter.py /opt/cmseek_adapter.py

ENTRYPOINT ["python3", "/opt/cmseek_adapter.py"]
