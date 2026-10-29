#!/bin/sh
# Container start: prepare the data volume, join the tailnet if configured, then run as an unprivileged user.
set -eu

DATA="${VMT_DATA_DIR:-/data}"
mkdir -p "$DATA"
# Platform volumes are usually mounted owned by root.
chown app:app "$DATA"

if [ -n "${TS_AUTHKEY:-}" ]; then
    mkdir -p "$DATA/tailscale"
    # Userspace mode needs no special container privileges. Nessus traffic goes through the local
    # HTTP proxy it opens; set proxy = "http://localhost:1055" under [nessus].
    tailscaled --tun=userspace-networking --statedir="$DATA/tailscale" \
        --outbound-http-proxy-listen=localhost:1055 >/tmp/tailscaled.log 2>&1 &
    if ! tailscale up --authkey="$TS_AUTHKEY" --hostname="${TS_HOSTNAME:-vmtoolkit}" --timeout=60s; then
        echo "Warning: could not join the tailnet; Nessus pulls will fail. tailscaled log:" >&2
        tail -n 20 /tmp/tailscaled.log >&2
    fi
fi

export HOME=/home/app
# The database holds vulnerability details: keep new files private to the app user.
umask 077
exec setpriv --reuid=app --regid=app --init-groups vmt serve "$@"
