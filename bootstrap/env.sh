#!/usr/bin/env bash
# Sourced by every script. Stores your choices in ../.nimbus-state (git-ignored).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="$HERE/../.nimbus-state"
export AWS_REGION="${AWS_REGION:-us-east-2}"; export AWS_DEFAULT_REGION="$AWS_REGION"
export AWS_PAGER=""
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"
case "$CALLER_ARN" in *:root) echo "STOP: you are using the ROOT user. Use your IAM lab user (Step 01)."; exit 1;; esac
[ -f "$STATE" ] && source "$STATE"
# Bucket names are global: account id makes yours unique.
BUCKET="${BUCKET:-lab01-nimbus-${ACCOUNT_ID}}"
LOGBUCKET="${LOGBUCKET:-lab01-logs-${ACCOUNT_ID}}"   # CloudTrail + S3 access logs
ALERT_REGION="us-east-1"                              # IAM and sign-in events are global: they arrive in us-east-1
render() {  # render <template> -> stdout with placeholders filled
  sed -e "s|__ACCOUNT_ID__|$ACCOUNT_ID|g" -e "s|__BUCKET__|$BUCKET|g" -e "s|__LOGBUCKET__|$LOGBUCKET|g" -e "s|__REGION__|$AWS_REGION|g" "$1"
}
POL="$HERE/policies"
CONF="$HERE/config"
