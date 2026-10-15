FROM python:3.12-slim

# jsrecon is a single stdlib-only script: it fetches the JavaScript assets whose
# URLs the worker feeds in on stdin and prints extracted artifacts as JSON lines.
# No third-party dependencies, so the image stays tiny and builds offline.
WORKDIR /opt/jsrecon
COPY jsrecon.py /opt/jsrecon/jsrecon.py

ENTRYPOINT ["python3", "/opt/jsrecon/jsrecon.py"]
CMD ["--help"]
