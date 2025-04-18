#!/bin/bash
set -e  # Exit on error

# If Y_SWEET_URL_PREFIX is not set but FLY_APP_NAME is, construct the URL
if [ -z "$Y_SWEET_URL_PREFIX" ] && [ -n "$FLY_APP_NAME" ]; then
    export Y_SWEET_URL_PREFIX="https://$FLY_APP_NAME.fly.dev"
    echo "🪽  Running on fly.io. Setting --url-prefix=$Y_SWEET_URL_PREFIX"
fi

if [ -n "$TAILSCALE_AUTHKEY" ]; then
    echo "🔑 Joining tailnet..."
    tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
    tailscale up --auth-key=${TAILSCALE_AUTHKEY} --hostname=relay-server
fi

echo "🛰️ Starting Relay Server..."
exec y-sweet "$@"
