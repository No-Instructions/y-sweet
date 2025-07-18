#!/bin/bash
set -e  # Exit on error

# Backwards compatibility for deprecated Y_SWEET_ variables
if [ -z "$RELAY_SERVER_URL" ] && [ -n "$Y_SWEET_URL_PREFIX" ]; then
    echo "⚠️  Y_SWEET_URL_PREFIX is deprecated. Please use RELAY_SERVER_URL" >&2
    export RELAY_SERVER_URL="$Y_SWEET_URL_PREFIX"
fi

# If RELAY_SERVER_URL is not set but FLY_APP_NAME is, construct the URL
if [ -z "$RELAY_SERVER_URL" ] && [ -n "$FLY_APP_NAME" ]; then
    export RELAY_SERVER_URL="https://$FLY_APP_NAME.fly.dev"
    echo "🪽  Running on fly.io. Setting --url-prefix=$RELAY_SERVER_URL"
fi

if [ -n "$TAILSCALE_AUTHKEY" ]; then
    echo "🔑 Joining tailnet..."
    tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
    tailscale up --auth-key=${TAILSCALE_AUTHKEY} --hostname=relay-server
fi

echo "🛰️ Starting Relay Server..."
exec y-sweet "$@"
