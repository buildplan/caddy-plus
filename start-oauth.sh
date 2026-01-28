#!/bin/sh

# Check if the mandatory Client ID is set
if [ -z "$OAUTH2_PROXY_CLIENT_ID" ]; then
    echo "---------------------------------------------------"
    echo "INFO: OAUTH2_PROXY_CLIENT_ID not set."
    echo "INFO: OIDC Integration is DISABLED."
    echo "INFO: This container will run without OIDC."
    echo "INFO: Enable it by setting env variables"
    echo "---------------------------------------------------"

    exec sleep infinity
fi

# If config exists, start normally
exec /usr/bin/oauth2-proxy --http-address="127.0.0.1:4180" --upstream="static://202" --reverse-proxy=true