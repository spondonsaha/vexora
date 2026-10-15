FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython==2.6.1 requests==2.32.3
COPY takeover.py /opt/takeover.py
ENTRYPOINT ["python", "/opt/takeover.py"]
