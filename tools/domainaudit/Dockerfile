FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython==2.6.1 requests==2.32.3
COPY audit.py /opt/audit.py
ENTRYPOINT ["python", "/opt/audit.py"]
