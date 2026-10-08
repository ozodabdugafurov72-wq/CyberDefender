FROM python:3.13-slim AS package
WORKDIR /source
COPY . .
RUN python scripts/build_distribution_package.py --output /artifacts/CyberDefenderPackage.zip

FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CYBERDEFENDER_DISTRIBUTION_HOST=0.0.0.0 \
    CYBERDEFENDER_DISTRIBUTION_DB=/data/distribution.db \
    CYBERDEFENDER_INSTALLER_PATH=/app/distribution/CyberDefenderPackage.zip
# The distribution service uses only the Python standard library.
COPY control_plane/__init__.py control_plane/distribution_server.py control_plane/distribution_repository.py ./control_plane/
COPY --from=package /artifacts/ ./distribution/
CMD ["python", "-m", "control_plane.distribution_server"]
