FROM autopatch-validator:latest
USER root
COPY docker/validation/acceptance-requirements.txt /opt/autopatch/acceptance-requirements.txt
RUN pip install --no-cache-dir -r /opt/autopatch/acceptance-requirements.txt \
    && chown -R 10001:10001 /tmp/autopatch-pycache
USER 10001:10001
