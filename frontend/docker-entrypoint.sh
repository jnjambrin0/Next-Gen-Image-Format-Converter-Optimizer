#!/bin/sh
set -e

# Replace environment variables in the built app
# This allows runtime configuration of the frontend

# Default values
API_HOST="${VITE_API_HOST:-localhost}"
API_PORT="${VITE_API_PORT:-8000}"

# Find and replace placeholders in JavaScript files
# Note: In production builds, Vite replaces import.meta.env variables at build time
# This script is for runtime replacement if needed

echo "Configuring frontend with API endpoint: http://${API_HOST}:${API_PORT}"

# If there's a config file that needs runtime replacement, do it here
# Example: sed -i "s|REPLACE_API_URL|http://${API_HOST}:${API_PORT}|g" /usr/share/nginx/html/config.js

# Execute the main command
exec "$@"