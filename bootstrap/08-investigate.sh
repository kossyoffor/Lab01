#!/usr/bin/env bash
# INCIDENT RESPONSE: one timeline for a username from three independent sources.
# Usage: ./08-investigate.sh <username>
source "$(dirname "$0")/env.sh"
U="${1:?usage: $0 <username>}"
echo "== 1. CloudTrail (AWS side: who did what to this IAM user, last 90 days, free)"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$U" --max-results 20 \
  --query 'Events[].[EventTime,EventName,Username]' --output table
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue="$U" --max-results 20 \
  --query 'Events[].[EventTime,EventName,Username]' --output table
echo "== 2. Registry audit trail (app side, S3)"
aws s3 ls "s3://$BUCKET/audit/" | grep -- "-$U.json" || echo "no audit entries for $U"
echo "== 3. Container logs (CloudWatch /lab01/app, structured JSON)"
aws logs filter-log-events --log-group-name /lab01/app --filter-pattern "\"$U\"" --max-items 20 \
  --query 'events[].message' --output text || echo "no log events yet"
