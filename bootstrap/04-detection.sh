#!/usr/bin/env bash
# LOGGING and ALERTING (all free tier): one CloudTrail trail (first copy of management events is free),
# plus EventBridge rules that email you through SNS when risky IAM calls or password-only sign-ins happen.
# Usage: ALERT_EMAIL=you@example.com ./04-detection.sh
source "$(dirname "$0")/env.sh"
ALERT_EMAIL="${ALERT_EMAIL:?set ALERT_EMAIL=you@example.com (alerts are emailed there)}"

# 1. CloudTrail: who called which AWS API. One trail, management events only, log file validation on.
render "$POL/log-bucket-policy.json" > /tmp/lbp.json; aws s3api put-bucket-policy --bucket "$LOGBUCKET" --policy file:///tmp/lbp.json
aws cloudtrail describe-trails --trail-name-list lab01-trail --query 'trailList[0].Name' --output text 2>/dev/null | grep -q lab01-trail || \
  aws cloudtrail create-trail --name lab01-trail --s3-bucket-name "$LOGBUCKET" --s3-key-prefix cloudtrail \
    --include-global-service-events --enable-log-file-validation --no-is-multi-region-trail >/dev/null
aws cloudtrail start-logging --name lab01-trail
echo "cloudtrail ready: lab01-trail -> s3://$LOGBUCKET/cloudtrail/"

# 2. SNS topic + email subscription (IAM and sign-in events are delivered in $ALERT_REGION).
TOPIC="$(aws sns create-topic --name lab01-security-alerts --region "$ALERT_REGION" --query TopicArn --output text)"
sed -e "s|__TOPIC_ARN__|$TOPIC|g" -e "s|__ACCOUNT_ID__|$ACCOUNT_ID|g" "$POL/sns-topic-policy.json" > /tmp/snspol.json
aws sns set-topic-attributes --region "$ALERT_REGION" --topic-arn "$TOPIC" --attribute-name Policy --attribute-value file:///tmp/snspol.json
aws sns subscribe --region "$ALERT_REGION" --topic-arn "$TOPIC" --protocol email --notification-endpoint "$ALERT_EMAIL" >/dev/null
echo "sns ready: confirm the subscription email sent to $ALERT_EMAIL"

# 3. EventBridge rules: risky IAM changes, and console sign-in without MFA.
rule() {  # rule <name> <pattern-file>
  aws events put-rule --region "$ALERT_REGION" --name "$1" --event-pattern "file://$CONF/$2" --state ENABLED >/dev/null
  sed -e "s|__TOPIC_ARN__|$TOPIC|g" -e "s|__RULE__|$1|g" "$CONF/eventtarget.json" > /tmp/target.json
  aws events put-targets --region "$ALERT_REGION" --rule "$1" --targets file:///tmp/target.json >/dev/null
  echo "rule ready: $1"
}
rule lab01-risky-iam eventpattern-iam.json
rule lab01-signin-without-mfa eventpattern-signin.json
echo "TOPIC_ARN=$TOPIC" >> "$STATE"
