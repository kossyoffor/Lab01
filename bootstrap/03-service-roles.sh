#!/usr/bin/env bash
# One EC2 instance role (can only AssumeRole) + one least-privilege role per microservice.
source "$(dirname "$0")/env.sh"
role() {  # role <name> <trust.json> <policy.json|"">
  render "$POL/$2" > /tmp/trust.json
  if aws iam get-role --role-name "$1" >/dev/null 2>&1; then
    aws iam update-assume-role-policy --role-name "$1" --policy-document file:///tmp/trust.json
  else
    aws iam create-role --role-name "$1" --path /nimbus/ --assume-role-policy-document file:///tmp/trust.json \
      --description "Nimbus lab" --tags Key=managed-by,Value=lab01 >/dev/null
  fi
  render "$POL/$3" > /tmp/rolepol.json
  aws iam put-role-policy --role-name "$1" --policy-name inline --policy-document file:///tmp/rolepol.json
  echo "role ready: $1"
}
role nimbus-ec2-instance ec2-trust.json ec2-instance-role.json
role nimbus-flowlogs flowlogs-trust.json flowlogs-role.json   # lets VPC Flow Logs write to /lab01/flow only
aws iam get-instance-profile --instance-profile-name nimbus-ec2-profile >/dev/null 2>&1 || {
  aws iam create-instance-profile --instance-profile-name nimbus-ec2-profile --path /nimbus/ >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name nimbus-ec2-profile --role-name nimbus-ec2-instance; }
echo "waiting 15s for IAM propagation..."; sleep 15
for S in web onboarding offboarding dashboard; do role "nimbus-$S-svc" svc-trust.json "svc-$S.json"; done
