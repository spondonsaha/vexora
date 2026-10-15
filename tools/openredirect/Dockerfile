FROM python:3.12-slim

# openredirect is a single stdlib-only script: it probes the parameterised URLs
# the worker feeds in on stdin and prints redirect findings as JSON lines.
# No third-party dependencies, so the image stays tiny and builds offline.
WORKDIR /opt/openredirect
COPY openredirect.py /opt/openredirect/openredirect.py

ENTRYPOINT ["python3", "/opt/openredirect/openredirect.py"]
CMD ["--help"]
