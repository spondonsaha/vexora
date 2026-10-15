FROM python:3.11-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r.git /opt/sublist3r
RUN pip install --no-cache-dir requests dnspython
COPY patch.py /tmp/patch.py
RUN python /tmp/patch.py
WORKDIR /opt/sublist3r
ENTRYPOINT ["python", "/opt/sublist3r/sublist3r.py"]
