# CyberDefender

Windows endpoint security agent, local owner dashboard, and distribution/fleet server.

## Windows package

Download `/download/cyberdefender` from your deployed Railway domain. This is a
source/install ZIP, not a compiled EXE or an offline installer. Python 3.13+ and
internet access for Python dependencies are required. Extract it, then follow
[README_INSTALL.md](README_INSTALL.md). The endpoint agent and owner dashboard
run on Windows; Railway hosts only the distribution/fleet service.

Build the same package locally:

```powershell
.\.venv\Scripts\python.exe scripts/build_distribution_package.py
```

Output: `dist/CyberDefenderPackage.zip` and its SHA-256 checksum. The explicit
`distribution-files.txt` manifest excludes local runtime state, credentials,
backups, and unrelated documents. Add new required source files to that manifest.
Native Rust/Go source is included; precompiled Windows native binaries are not.

## Railway server settings

1. Create a service from `ozodabdugafurov72-wq/CyberDefender`, branch `main`.
2. Keep the root directory at `/`. Railway reads `railway.toml` and `Dockerfile`.
3. Attach a persistent volume at `/data` for download/fleet SQLite data.
4. Use one replica. Start command: `python -m control_plane.distribution_server`.
5. Healthcheck path: `/health`. The server listens on `0.0.0.0` and Railway's `PORT`.
6. In Settings > Networking, choose **Generate Domain**.

The Docker build creates and includes the Windows package automatically. No
`package.json` is needed: the hosted Python service uses the standard library.
The Windows dependency list is `requirements.txt`.

| Setting | Value |
| --- | --- |
| Builder | Dockerfile |
| Dockerfile path | `Dockerfile` |
| Start command | `python -m control_plane.distribution_server` |
| Healthcheck | `/health` |
| Volume mount | `/data` |
| Replicas | `1` |
| `CYBERDEFENDER_DISTRIBUTION_DB` | `/data/distribution.db` (image default) |
| `CYBERDEFENDER_INSTALLER_PATH` | `/app/distribution/CyberDefenderPackage.zip` (image default) |
| `CYBERDEFENDER_FLEET_TOKEN` | Optional secret for authenticated enrollment/heartbeat POSTs |

Without a fleet token, downloads and health checks work, but fleet POSTs reject
all requests. Set a strong token using Railway's secret variables when enabling
fleet writes; never commit it. Windows endpoints need the matching token and
remote server URL configured separately. Existing local token-file support remains.

After Railway assigns your domain:

- Server: `https://<your-domain>`
- Health: `https://<your-domain>/health`
- Package: `https://<your-domain>/download/cyberdefender`

The domain above is a placeholder, not a deployed URL.

Railway references: [config as code](https://docs.railway.com/config-as-code),
[healthchecks](https://docs.railway.com/deployments/healthchecks),
[public networking](https://docs.railway.com/networking/public-networking).
