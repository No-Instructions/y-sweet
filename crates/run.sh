#!/bin/bash
set -e  # Exit on error

# Handle signals properly
trap "exit" TERM INT

# If Y_SWEET_URL_PREFIX is not set but FLY_APP_NAME is, construct the URL
if [ -z "$Y_SWEET_URL_PREFIX" ] && [ -n "$FLY_APP_NAME" ]; then
    export Y_SWEET_URL_PREFIX="https://$FLY_APP_NAME.fly.dev"
    echo "🪽  Running on fly.io. Setting --url-prefix=$Y_SWEET_URL_PREFIX"
fi

# If Y_SWEET_STORE is not set, default to local /data
if [ -z "$Y_SWEET_STORE" ]; then
    export Y_SWEET_STORE=/data
fi
echo "💾 Persisting data to $Y_SWEET_STORE"

if [ -n "$TAILSCALE_AUTHKEY" ]; then
    echo "🔑 Joining tailnet..."
    if [ -n "$TAILSCALE_USERSPACE_NETWORKING" ]; then
        tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
    else
        tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
    fi
    tailscale up --auth-key=${TAILSCALE_AUTHKEY} --hostname=relay-server
    if [ -n "$TAILSCALE_SERVE" ]; then
        tailscale serve --bg localhost:8080
    fi
fi
echo "🛰️  Starting Relay Server..."
exec y-sweet serve --host=0.0.0.0 --prod
