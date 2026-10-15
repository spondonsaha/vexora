FROM projectdiscovery/nuclei:latest
# Bake the community templates into a fixed directory so runs are fully offline
# and don't depend on the template release channel at scan time.
RUN nuclei -update-templates -update-template-dir /opt/nuclei-templates -nc
