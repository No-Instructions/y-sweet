#!/bin/bash
set -e  # Exit on error

# Handle signals properly
trap "exit" TERM INT

# Backwards compatibility for deprecated Y_SWEET_ variables
use_legacy_var() {
    local new_var=$1
    local old_var=$2
    if [ -z "$(eval echo \$$new_var)" ] && [ -n "$(eval echo \$$old_var)" ]; then
        echo "⚠️  $old_var is deprecated. Please use $new_var" >&2
        eval export $new_var="\$$old_var"
    fi
}

use_legacy_var RELAY_URL_PREFIX Y_SWEET_URL_PREFIX
use_legacy_var RELAY_STORAGE Y_SWEET_STORE

# If RELAY_URL_PREFIX is not set but FLY_APP_NAME is, construct the URL
if [ -z "$RELAY_URL_PREFIX" ] && [ -n "$FLY_APP_NAME" ]; then
    export RELAY_URL_PREFIX="https://$FLY_APP_NAME.fly.dev"
    echo "🪽  Running on fly.io. Setting --url-prefix=$RELAY_URL_PREFIX"
fi

# RELAY_STORAGE is required
if [ -z "$RELAY_STORAGE" ]; then
    echo "RELAY_STORAGE environment variable is required" >&2
    exit 1
fi
echo "💾 Persisting data to $RELAY_STORAGE"

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
