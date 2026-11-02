#!/usr/bin/env bash
# Data bucket + log bucket (private, versioned, encrypted, TLS only, lifecycle, access logging),
# two Secrets Manager secrets, and two CloudWatch log groups (7 day retention).
source "$(dirname "$0")/env.sh"

mkbucket() {  # mkbucket <name>  : private + encrypted, never public
  aws s3api head-bucket --bucket "$1" 2>/dev/null || aws s3api create-bucket --bucket "$1" --region "$AWS_REGION" \
    --create-bucket-configuration LocationConstraint="$AWS_REGION" >/dev/null
  aws s3api put-public-access-block --bucket "$1" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws s3api put-bucket-encryption --bucket "$1" --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
}
mkbucket "$BUCKET"; mkbucket "$LOGBUCKET"
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled
# DATA: TLS only (deny plain http and TLS older than 1.2), on both buckets
render "$POL/data-bucket-policy.json" > /tmp/dbp.json; aws s3api put-bucket-policy --bucket "$BUCKET" --policy file:///tmp/dbp.json
render "$POL/log-bucket-policy.json"  > /tmp/lbp.json; aws s3api put-bucket-policy --bucket "$LOGBUCKET" --policy file:///tmp/lbp.json
# DATA: old versions expire after 30 days, logs after 30 days (keeps storage inside 5 GB free)
aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" --lifecycle-configuration "file://$CONF/lifecycle-data.json"
aws s3api put-bucket-lifecycle-configuration --bucket "$LOGBUCKET" --lifecycle-configuration "file://$CONF/lifecycle-logs.json"
# LOGGING: who touched the registry bucket (S3 server access logs go to the log bucket)
aws s3api put-bucket-logging --bucket "$BUCKET" --bucket-logging-status \
  "{\"LoggingEnabled\":{\"TargetBucket\":\"$LOGBUCKET\",\"TargetPrefix\":\"s3-access/\"}}"
echo "buckets ready: $BUCKET (data) and $LOGBUCKET (logs): private, encrypted, TLS only, lifecycle, access logged"
# LOGGING: CloudWatch log groups for container logs and flow logs, short retention
for G in /lab01/app /lab01/flow; do
  aws logs create-log-group --log-group-name "$G" 2>/dev/null || true
  aws logs put-retention-policy --log-group-name "$G" --retention-in-days 7
done
echo "log groups ready: /lab01/app /lab01/flow (7 day retention)"

rand() { head -c 256 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9' | cut -c1-"$1"; }
if ! aws secretsmanager describe-secret --secret-id nimbus/internal-token >/dev/null 2>&1; then
  aws secretsmanager create-secret --name nimbus/internal-token \
    --description "Service-to-service token (Nimbus lab)" --secret-string "$(rand 48)" >/dev/null
  echo "secret created: nimbus/internal-token"
fi
if ! aws secretsmanager describe-secret --secret-id nimbus/web-login >/dev/null 2>&1; then
  ADMIN_PW="$(rand 24)"
  aws secretsmanager create-secret --name nimbus/web-login \
    --description "Nimbus console admin login + Flask session key" \
    --secret-string "{\"admin_username\":\"admin\",\"admin_password\":\"$ADMIN_PW\",\"flask_secret_key\":\"$(rand 48)\"}" >/dev/null
  echo "secret created: nimbus/web-login"
  echo "Console login -> user: admin   password: $ADMIN_PW   (retrieve later with: aws secretsmanager get-secret-value --secret-id nimbus/web-login)"
fi
printf "BUCKET=%s\nLOGBUCKET=%s\n" "$BUCKET" "$LOGBUCKET" > "$STATE"
