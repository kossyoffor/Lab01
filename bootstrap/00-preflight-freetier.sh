#!/usr/bin/env bash
# Run BEFORE the lab (and again after cleanup). Read-only. Fails loudly if something
# in the account would make this lab cost money.
source "$(dirname "$0")/env.sh"
fail=0; ok(){ echo "  OK    $*"; }; bad(){ echo "  FAIL  $*"; fail=1; }; warn(){ echo "  WARN  $*"; }
echo "Account $ACCOUNT_ID  region $AWS_REGION  caller $CALLER_ARN"

# 1. Region: free-tier eligible instance type must exist here.
T=""; for X in t3.micro t2.micro t4g.micro; do
  [ "$(aws ec2 describe-instance-types --instance-types $X --query 'InstanceTypes[0].FreeTierEligible' --output text 2>/dev/null | tr A-Z a-z)" = true ] && { T=$X; break; }; done
[ -n "$T" ] && ok "free-tier eligible instance type: $T" || bad "no free-tier eligible instance type in $AWS_REGION"

# 2. Nothing else already burning the 750 free instance-hours.
N=$(aws ec2 describe-instances --filters Name=instance-state-name,Values=pending,running --query 'length(Reservations[].Instances[])' --output text)
[ "$N" = 0 ] && ok "no other running EC2 instances" || warn "$N EC2 instance(s) already running: free hours are shared across ALL of them"

# 3. Paid-by-the-hour extras that are NOT free tier.
EIP=$(aws ec2 describe-addresses --query 'length(Addresses)' --output text); [ "$EIP" = 0 ] && ok "no Elastic IPs" || warn "$EIP Elastic IP(s) exist (idle/extra public IPv4 costs money)"
NAT=$(aws ec2 describe-nat-gateways --filter Name=state,Values=available --query 'length(NatGateways)' --output text); [ "$NAT" = 0 ] && ok "no NAT gateways" || warn "$NAT NAT gateway(s) running (paid)"

# 4. Secrets Manager is the one service with a per-secret fee after trial/credits.
S=$(aws secretsmanager list-secrets --query 'length(SecretList)' --output text)
echo "  INFO  $S secret(s) in this region; the lab adds 2 (about \$0.40 each per month, prorated - cleanup deletes them)"

# 4b. CloudTrail: the first trail of management events is free, a second trail is billed.
TR=$(aws cloudtrail describe-trails --query 'length(trailList[?Name!=`lab01-trail`])' --output text 2>/dev/null || echo 0)
[ "$TR" = 0 ] && ok "no other CloudTrail trails (the lab adds the one free trail)" || warn "$TR other trail(s) exist: a second copy of management events is NOT free. Do not run 04-detection.sh until you decide"

# 5. Budget alert from Step 01.
B=$(aws budgets describe-budgets --account-id "$ACCOUNT_ID" --query 'length(Budgets)' --output text 2>/dev/null || echo 0)
[ "$B" != 0 ] && [ "$B" != None ] && ok "budget alert exists" || bad "no AWS Budget found - create the alert from Step 01 first"

# 6. Leftovers from a previous attempt.
aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null && warn "bucket $BUCKET already exists (previous run?)" || ok "bucket name free"
[ $fail = 0 ] && echo "PREFLIGHT PASSED" || { echo "PREFLIGHT FAILED - fix the items above before continuing"; exit 1; }
