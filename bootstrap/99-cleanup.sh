#!/usr/bin/env bash
# Deletes EVERYTHING the lab created (and every IAM user the app onboarded). Safe to re-run.
source "$(dirname "$0")/env.sh"
read -r -p "Delete the Nimbus lab from account $ACCOUNT_ID? type yes: " ok; [ "$ok" = yes ] || exit 1
for ID in $(aws ec2 describe-instances --filters Name=tag:Name,Values=lab01 Name=instance-state-name,Values=pending,running,stopped \
   --query 'Reservations[].Instances[].InstanceId' --output text); do aws ec2 terminate-instances --instance-ids $ID >/dev/null; aws ec2 wait instance-terminated --instance-ids $ID; echo "terminated $ID"; done
# flow logs, S3 endpoint, trail, alerts, log groups
for F in $(aws ec2 describe-flow-logs --filter Name=log-group-name,Values=/lab01/flow --query 'FlowLogs[].FlowLogId' --output text); do aws ec2 delete-flow-logs --flow-log-ids $F >/dev/null && echo "deleted flow log $F"; done
for E in $(aws ec2 describe-vpc-endpoints --filters Name=tag:Name,Values=lab01-s3 --query 'VpcEndpoints[].VpcEndpointId' --output text); do aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $E >/dev/null && echo "deleted endpoint $E"; done
aws cloudtrail delete-trail --name lab01-trail 2>/dev/null && echo "deleted trail" || true
for R in lab01-risky-iam lab01-signin-without-mfa; do
  aws events remove-targets --region $ALERT_REGION --rule $R --ids email-the-security-topic >/dev/null 2>&1 || true
  aws events delete-rule --region $ALERT_REGION --name $R 2>/dev/null && echo "deleted rule $R" || true; done
for T in $(aws sns list-topics --region $ALERT_REGION --query 'Topics[?ends_with(TopicArn,`lab01-security-alerts`)].TopicArn' --output text); do aws sns delete-topic --region $ALERT_REGION --topic-arn $T && echo "deleted topic"; done
for G in /lab01/app /lab01/flow; do aws logs delete-log-group --log-group-name $G 2>/dev/null && echo "deleted log group $G" || true; done
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=nimbus-sg --query 'SecurityGroups[0].GroupId' --output text); [ "$SG" != None ] && aws ec2 delete-security-group --group-id $SG && echo "deleted sg"
# IAM users created by the app
for U in $(aws iam list-users --path-prefix /nimbus/ --query 'Users[].UserName' --output text); do
  for P in $(aws iam list-attached-user-policies --user-name $U --query 'AttachedPolicies[].PolicyArn' --output text); do aws iam detach-user-policy --user-name $U --policy-arn $P; done
  for G in $(aws iam list-groups-for-user --user-name $U --query 'Groups[].GroupName' --output text); do aws iam remove-user-from-group --user-name $U --group-name $G; done
  for K in $(aws iam list-access-keys --user-name $U --query 'AccessKeyMetadata[].AccessKeyId' --output text); do aws iam delete-access-key --user-name $U --access-key-id $K; done
  for M in $(aws iam list-mfa-devices --user-name $U --query 'MFADevices[].SerialNumber' --output text); do aws iam deactivate-mfa-device --user-name $U --serial-number $M; aws iam delete-virtual-mfa-device --serial-number $M; done
  aws iam delete-login-profile --user-name $U 2>/dev/null || true; aws iam delete-user --user-name $U; echo "deleted user $U"
done
for G in TechTeam BusinessTeam SecurityTeam; do
  for P in $(aws iam list-attached-group-policies --group-name $G --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do aws iam detach-group-policy --group-name $G --policy-arn $P; done
  aws iam delete-group --group-name $G 2>/dev/null && echo "deleted group $G"; done
for P in Nimbus-RequireMFA Nimbus-DenyAll TechTeam-DevScoped BusinessTeam-ReadOnly SecurityTeam-IAMAudit; do
  A="arn:aws:iam::$ACCOUNT_ID:policy/nimbus/$P"
  for V in $(aws iam list-policy-versions --policy-arn $A --query 'Versions[?IsDefaultVersion==`false`].VersionId' --output text 2>/dev/null); do aws iam delete-policy-version --policy-arn $A --version-id $V; done
  aws iam delete-policy --policy-arn $A 2>/dev/null && echo "deleted policy $P"; done
for R in nimbus-web-svc nimbus-onboarding-svc nimbus-offboarding-svc nimbus-dashboard-svc nimbus-flowlogs nimbus-ec2-instance; do
  aws iam delete-role-policy --role-name $R --policy-name inline 2>/dev/null || true
  [ $R = nimbus-ec2-instance ] && { aws iam remove-role-from-instance-profile --instance-profile-name nimbus-ec2-profile --role-name $R 2>/dev/null || true; aws iam delete-instance-profile --instance-profile-name nimbus-ec2-profile 2>/dev/null || true; }
  aws iam delete-role --role-name $R 2>/dev/null && echo "deleted role $R"; done
for S in nimbus/internal-token nimbus/web-login; do aws secretsmanager delete-secret --secret-id $S --force-delete-without-recovery >/dev/null 2>&1 && echo "deleted secret $S"; done
# versioned buckets: remove every version + delete marker, then the buckets
aws s3api put-bucket-logging --bucket "$BUCKET" --bucket-logging-status '{}' 2>/dev/null || true   # stop writing new access logs first
for B in "$BUCKET" "$LOGBUCKET"; do
  aws s3api delete-bucket-policy --bucket "$B" 2>/dev/null || true   # drop the TLS only rule so cleanup works over any endpoint
  for PASS in 1 2 3; do    # late log files can arrive after the first pass, so empty again
    for T in Versions DeleteMarkers; do
      J=$(aws s3api list-object-versions --bucket "$B" --query "{Objects:$T[].{Key:Key,VersionId:VersionId}}" --output json 2>/dev/null || echo '{"Objects":null}')
      echo "$J" | grep -q '"Objects": null' || aws s3api delete-objects --bucket "$B" --delete "$J" >/dev/null
    done
    aws s3api delete-bucket --bucket "$B" 2>/dev/null && { echo "deleted bucket $B"; break; }
    sleep 3
  done
done
aws s3api head-bucket --bucket "$LOGBUCKET" 2>/dev/null && echo "NOTE: $LOGBUCKET still receives late log files. It holds a few KB and expires them itself; run this script again tomorrow to remove it."
rm -f "$STATE"; echo "Cleanup complete. Verify in the console: EC2, S3, Secrets Manager, IAM."
