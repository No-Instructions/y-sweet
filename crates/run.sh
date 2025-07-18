#!/bin/bash
set -e  # Exit on error

# Handle signals properly
trap "exit" TERM INT

# Backwards compatibility for deprecated Y_SWEET_ variables
if [ -z "$RELAY_URL_PREFIX" ] && [ -n "$Y_SWEET_URL_PREFIX" ]; then
    echo "⚠️  Y_SWEET_URL_PREFIX is deprecated. Please use RELAY_URL_PREFIX" >&2
    export RELAY_URL_PREFIX="$Y_SWEET_URL_PREFIX"
fi
if [ -z "$RELAY_STORE" ] && [ -n "$Y_SWEET_STORE" ]; then
    echo "⚠️  Y_SWEET_STORE is deprecated. Please use RELAY_STORE" >&2
    export RELAY_STORE="$Y_SWEET_STORE"
fi

# If RELAY_URL_PREFIX is not set but FLY_APP_NAME is, construct the URL
if [ -z "$RELAY_URL_PREFIX" ] && [ -n "$FLY_APP_NAME" ]; then
    export RELAY_URL_PREFIX="https://$FLY_APP_NAME.fly.dev"
    echo "🪽  Running on fly.io. Setting --url-prefix=$RELAY_URL_PREFIX"
fi

# If RELAY_STORE is not set, default to local /data
if [ -z "$RELAY_STORE" ]; then
    export RELAY_STORE=/data
fi
echo "💾 Persisting data to $RELAY_STORE"

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
