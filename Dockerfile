FROM python:3.13-slim AS package
WORKDIR /source
RUN pip install --no-cache-dir cryptography==50.0.2
COPY . .
RUN python scripts/scan_repository_secrets.py
RUN python -B -m unittest \
    tests.test_distribution_security_contract \
    tests.test_fleet_protocol_security \
    tests.test_cloud_soc_v2_security \
    tests.test_cloud_soc_v2_http -v
RUN python scripts/build_distribution_package.py --output /artifacts/CyberDefenderPackage.zip

FROM python:3.13-slim
WORKDIR /app
RUN pip install --no-cache-dir cryptography==50.0.2
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CYBERDEFENDER_DISTRIBUTION_HOST=0.0.0.0 \
    CYBERDEFENDER_DISTRIBUTION_DB=/data/distribution.db \
    CYBERDEFENDER_INSTALLER_PATH=/app/distribution/CyberDefenderPackage.zip
COPY control_plane/__init__.py \
    control_plane/cloud_soc_v2.py \
    control_plane/distribution_server.py \
    control_plane/distribution_repository.py \
    control_plane/fleet_protocol.py \
    control_plane/xdr_compat.py \
    ./control_plane/
COPY --from=package /artifacts/ ./distribution/
CMD ["python", "-m", "control_plane.distribution_server"]
