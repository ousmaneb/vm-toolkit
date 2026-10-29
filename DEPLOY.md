# Deploying vmtoolkit

The toolkit runs as one container built from the `Dockerfile` in this repository. The same image runs
on Railway, Azure Container Apps and AWS ECS. Only how you set variables and attach storage differs.

## What runs in the container

- **`vmt serve`** runs the dashboard on `$PORT`. Every day at `[daily] time` (local time, set by `TZ`)
  it runs `vmt daily` and then `vmt backup`. If the container was off at that time, both run when it
  next starts.
- **All data lives in `/data`:** the database, history, reports, logs, raw Nessus downloads,
  backups and the Tailscale node state. Mount persistent storage there.
- **Single instance:** run exactly one copy, because SQLite allows one writer.
- **Production mode:** the image sets `VMT_ENV=production`. Sign-in is always required, demo data is
  turned off, and the dashboard only shows the live database.
- **Unprivileged user:** the app runs as `app` (uid 10001). The entrypoint starts as root only to
  set up `/data` and Tailscale.

## Settings and secrets

Nothing about your environment goes in the repository. The repository is public, and
`config.toml`, `.env` and `data/` are git-ignored. Everything comes from environment variables:

| Variable | Needed | What it is |
|---|---|---|
| `VMT_CONFIG_TOML` | yes | The whole `config.toml`, as text. See the example below. |
| `TZ` | yes | Time zone for the daily run, e.g. `America/New_York`. Defaults to UTC. |
| `VMT_ADMIN_USER`, `VMT_ADMIN_PASSWORD` | first deploy | Creates the first dashboard account, only while there are no accounts. Remove the password variable after signing in. |
| `TS_AUTHKEY` | for Nessus | Tailscale auth key; see below. |
| `TS_HOSTNAME` | no | Name of the container on your tailnet (default `vmtoolkit`). |
| `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY` | for Nessus | Nessus API keys. |
| `NESSUS_CA_CERT` | for Nessus | The Nessus CA certificate (PEM text, from `https://<nessus>:8834/getcert`). |
| `SLACK_WEBHOOK_URL` or `SMTP_USERNAME`, `SMTP_PASSWORD` | strongly recommended | Alerts, including the alert sent when a daily run fails. |
| `LLM_API_KEY` | no | Only for the LLM features. |
| `NVD_API_KEY`, `GITHUB_TOKEN` | no | Faster NVD lookups and GitHub searches. |
| `JIRA_EMAIL`, `JIRA_API_TOKEN`, `SN_USERNAME`, `SN_PASSWORD` | no | Only to push tickets. |
| `PORT` | set by the platform | Port the dashboard listens on (default 8501). |

Example `VMT_CONFIG_TOML`:

```toml
[nessus]
url = "https://nessus01:8834"
proxy = "http://localhost:1055"    # Tailscale's proxy inside the container

[daily]
time = "06:30"
report_weekday = "monday"

[alerts]
channels = ["slack"]

[sla_days]
critical = 15
high = 30
medium = 90
low = 180

[assets.web-01]
criticality = "high"
internet_facing = true
```

## Reaching Nessus through Tailscale

Nessus stays inside your network and is never exposed to the internet. The container joins your
tailnet and reaches Nessus privately.

1. **Install Tailscale** on the Nessus server, or on a subnet router that can reach it.
2. **Create an auth key** in the Tailscale admin console (Settings > Keys):
   - Reusable: yes, so redeploys can rejoin.
   - Pre-approved: yes.
   - Tag: `tag:vmtoolkit`.

   Store the key as `TS_AUTHKEY`. The node identity is kept in `/data/tailscale`, so redeploys keep
   the same machine on the tailnet.
3. **Restrict access** in the tailnet policy, so the container can reach only Nessus:

   ```json
   {"action": "accept", "src": ["tag:vmtoolkit"], "dst": ["nessus01:8834"]}
   ```

4. **Point the config at Nessus:** set `[nessus] url` to the Nessus server's tailnet name and
   `proxy = "http://localhost:1055"`.
   - The container runs Tailscale in userspace mode, which needs no special privileges and works on
     every platform. Nessus requests go through its local proxy.
   - The certificate check needs the name in `url` to match the name on the Nessus certificate. If
     they differ, issue a new certificate for the tailnet name with `nessuscli mkcert` on the Nessus
     server.

Then check the connection from a shell in the container (see below): run `vmt nessus check`.

## Railway

1. Push this repository to GitHub.
2. In Railway, create a new project and choose **Deploy from GitHub repo**. Railway builds the
   `Dockerfile` and reads `railway.json`, which sets one replica, the health check
   (`/_stcore/health`) and restart on failure.
3. On the service, add a **Volume** mounted at `/data`.
4. Under **Variables**, add the variables from the table above.
5. Under **Settings > Networking**, generate a domain. Railway serves it over HTTPS.
6. Open the domain and sign in with `VMT_ADMIN_USER` and `VMT_ADMIN_PASSWORD`. Then delete the
   `VMT_ADMIN_PASSWORD` variable.

**Accounts.** Each person gets their own account. Open a shell in the container with
`railway ssh`, then run:

```sh
su app -s /bin/sh -c 'vmt users add alice'      # asks for the password twice
su app -s /bin/sh -c 'vmt users list'
su app -s /bin/sh -c 'vmt users passwd alice'   # also unlocks a locked account
su app -s /bin/sh -c 'vmt users remove alice'
```

How sign-in works:

- Passwords must be at least 12 characters and are stored as salted scrypt hashes.
- Five wrong passwords lock the account for 15 minutes.
- A session lasts up to 8 hours. Reloading the browser tab asks you to sign in again.
- Sign-ins, failed sign-ins and every tool run (with the username) are written to the service log.

**Updating.** Push to GitHub and Railway redeploys. The volume, and with it all data and history,
is kept.

## Backups

`vmt serve` writes a dated copy of the database to `/data/backups/` after each daily run and keeps
the newest 14. Those copies sit on the same volume as the database. They protect against mistakes
and corruption, but not against losing the volume. For that:

- **Railway:** turn on volume backups on the service.
- **Anywhere:** copy `/data/backups/` and `/data/raw/` off the platform regularly.

To restore, stop the service, copy a backup over `/data/vmt.db`, and start it again.

## Moving to Azure or AWS

Use the same image and the same variables. Only these pieces change:

| | Azure Container Apps | AWS ECS on Fargate |
|---|---|---|
| Image | Build and push to Azure Container Registry | Build and push to ECR |
| `/data` | Azure Files share mounted at `/data`. Use an NFS share: SQLite locking is unreliable on SMB shares. | EFS file system mounted at `/data` |
| Secrets | Key Vault references in the app's secrets, mapped to environment variables | Secrets Manager or Parameter Store values in the task definition |
| HTTPS | Built-in ingress, target port = `PORT` | Application Load Balancer with an ACM certificate |
| Health check | Probe on `/_stcore/health` | Target group health check on `/_stcore/health` |
| Shell for `vmt users` | `az containerapp exec` | ECS Exec |
| Instances | min = max = 1 replica | desired count 1 |

Tailscale works the same way on both, because userspace mode needs no extra container privileges.
AWS App Runner and Azure App Service without mounted storage are not suitable: they have no
persistent volume for `/data`.

## Local development

The same image runs locally:

```sh
docker build -t vmtoolkit .
docker run -p 8080:8080 -v vmt-data:/data -e PORT=8080 \
  -e VMT_ADMIN_USER=admin -e VMT_ADMIN_PASSWORD='choose-a-long-one' \
  -e VMT_CONFIG_TOML="$(cat config.toml)" vmtoolkit
```

`requirements.lock` pins every dependency for the image. After changing dependencies in
`pyproject.toml`, regenerate it inside the same base image:

```sh
docker run --rm -v "$PWD":/src:ro python:3.12.10-slim-bookworm sh -c \
  'cp -r /src /tmp/b && cd /tmp/b && pip install -q ".[dashboard,ml,llm,report]" && pip freeze --exclude-editable | grep -v "^vmtoolkit"' \
  > requirements.lock
```
