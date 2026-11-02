#!/usr/bin/env bash
# Read-only snapshot of what the lab is consuming, to compare against free-tier limits.
source "$(dirname "$0")/env.sh"
echo "== EC2 (free: 750 h/month of one eligible instance, 30 GB EBS)"
aws ec2 describe-instances --filters Name=tag:Name,Values=lab01 Name=instance-state-name,Values=pending,running,stopped \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name,LaunchTime]' --output table
aws ec2 describe-volumes --filters Name=tag:Name,Values=lab01 --query 'Volumes[].[VolumeId,Size,VolumeType]' --output table 2>/dev/null || true
echo "== S3 (free: 5 GB, 20k GET, 2k PUT per month)"
aws s3 ls "s3://$BUCKET" --recursive --summarize 2>/dev/null | tail -2 || echo "bucket not found"
echo "== Secrets Manager (NOT always free: ~\$0.40/secret/month)"
aws secretsmanager list-secrets --query 'SecretList[?starts_with(Name,`nimbus/`)].[Name,CreatedDate]' --output table
echo "== IAM objects (IAM itself is free)"
aws iam list-users --path-prefix /nimbus/ --query 'length(Users)' --output text | sed 's/^/users under \/nimbus\/: /'
echo "Console view: Billing > Free Tier (usage vs limits)."
