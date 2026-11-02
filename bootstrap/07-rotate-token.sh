#!/usr/bin/env bash
# DATA: rotate the service to service token with zero downtime. Secrets Manager keeps the old value as
# AWSPREVIOUS, and the services accept current or previous, so no restart is needed.
source "$(dirname "$0")/env.sh"
NEW="$(head -c 256 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9' | cut -c1-48)"
aws secretsmanager put-secret-value --secret-id nimbus/internal-token --secret-string "$NEW" >/dev/null
aws secretsmanager describe-secret --secret-id nimbus/internal-token --query 'VersionIdsToStages' --output json
echo "rotated: new value is AWSCURRENT, old value is AWSPREVIOUS. Services pick it up within about a minute."
