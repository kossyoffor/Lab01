#!/usr/bin/env bash
# Usage: ./05-launch-ec2.sh https://github.com/<you>/<repo>.git   (repo must be PUBLIC - it holds no secrets)
source "$(dirname "$0")/env.sh"
REPO_URL="${1:?usage: $0 <public https git url of YOUR repo>}"
MYIP="$(curl -s https://checkip.amazonaws.com | tr -d '\n')/32"

# Free-tier guard: only launch an instance type AWS itself marks free-tier eligible.
TYPE=""
for T in t3.micro t2.micro t4g.micro; do
  [ "$(aws ec2 describe-instance-types --instance-types $T --query 'InstanceTypes[0].FreeTierEligible' --output text 2>/dev/null | tr 'A-Z' 'a-z')" = "true" ] && { TYPE=$T; break; }
done
[ -n "$TYPE" ] || { echo "No free-tier-eligible instance type found in $AWS_REGION. Stop and ask for help."; exit 1; }
ARCH=amd64; [ "$TYPE" = t4g.micro ] && ARCH=arm64
AMI="$(aws ssm get-parameter --name /aws/service/canonical/ubuntu/server/24.04/stable/current/$ARCH/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)"

VPC="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
[ "$VPC" != "None" ] || { echo "No default VPC in $AWS_REGION."; exit 1; }
SG="$(aws ec2 describe-security-groups --filters Name=group-name,Values=nimbus-sg Name=vpc-id,Values=$VPC --query 'SecurityGroups[0].GroupId' --output text)"
if [ "$SG" = "None" ]; then
  SG="$(aws ec2 create-security-group --group-name nimbus-sg --description 'Nimbus lab' --vpc-id $VPC --query GroupId --output text)"
fi
# NETWORK: one inbound port (HTTPS 8443) from YOUR address only. No SSH, no key pair: nothing to log in to.
aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 8443 --cidr "$MYIP" 2>/dev/null || true
# NETWORK: egress filtering. Replace the default allow-all outbound rule with HTTPS and HTTP only
# (HTTPS for AWS APIs and GitHub, HTTP for the Ubuntu package mirrors). DNS and the metadata service are not filtered by SGs.
aws ec2 revoke-security-group-egress --group-id "$SG" --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]' 2>/dev/null || true
aws ec2 authorize-security-group-egress --group-id "$SG" --ip-permissions \
  'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}]' 'IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0}]' 2>/dev/null || true
# NETWORK: S3 gateway endpoint (free). S3 traffic stays on the AWS network, and the endpoint policy allows ONLY our bucket.
RT="$(aws ec2 describe-route-tables --filters Name=vpc-id,Values=$VPC Name=association.main,Values=true --query 'RouteTables[0].RouteTableId' --output text)"
EP="$(aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=$VPC Name=tag:Name,Values=lab01-s3 --query 'VpcEndpoints[0].VpcEndpointId' --output text)"
if [ "$EP" = "None" ]; then
  render "$POL/s3-endpoint-policy.json" > /tmp/epol.json
  aws ec2 create-vpc-endpoint --vpc-id "$VPC" --vpc-endpoint-type Gateway --service-name "com.amazonaws.$AWS_REGION.s3" \
    --route-table-ids "$RT" --policy-document file:///tmp/epol.json --tag-specifications 'ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=lab01-s3}]' >/dev/null
  echo "s3 gateway endpoint created"
fi

sed -e "s|__REPO_URL__|$REPO_URL|g" -e "s|__REGION__|$AWS_REGION|g" -e "s|__BUCKET__|$BUCKET|g" -e "s|__MYIP__|$MYIP|g" "$HERE/user-data.sh" > /tmp/user-data.sh
# Free-tier guard: never run two lab instances (750 free hours/month covers ONE instance).
EXISTING="$(aws ec2 describe-instances --filters Name=tag:Name,Values=lab01 Name=instance-state-name,Values=pending,running --query 'length(Reservations[].Instances[])' --output text)"
[ "$EXISTING" = "0" ] || { echo "A lab01 instance is already running. Not launching a second one."; exit 1; }
HOURS="${AUTO_SHUTDOWN_HOURS:-8}"     # safety net: the server terminates itself after N hours
sed -i "s|__SHUTDOWN_MIN__|$((HOURS*60))|g" /tmp/user-data.sh
ID="$(aws ec2 run-instances --count 1 --image-id "$AMI" --instance-type "$TYPE" --security-group-ids "$SG" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=8,VolumeType=gp3,DeleteOnTermination=true}' \
  --instance-initiated-shutdown-behavior terminate \
  --iam-instance-profile Name=nimbus-ec2-profile \
  --metadata-options HttpTokens=required,HttpPutResponseHopLimit=2,HttpEndpoint=enabled \
  --user-data file:///tmp/user-data.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=lab01}]' 'ResourceType=volume,Tags=[{Key=Name,Value=lab01}]' \
  --query 'Instances[0].InstanceId' --output text)"
echo "INSTANCE_ID=$ID" >> "$STATE"
aws ec2 wait instance-running --instance-ids "$ID"
IP="$(aws ec2 describe-instances --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
ENI="$(aws ec2 describe-instances --instance-ids "$ID" --query 'Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId' --output text)"
# LOGGING: VPC flow logs, REJECTED traffic only, on this instance's network interface only (tiny volume, free).
aws ec2 create-flow-logs --resource-type NetworkInterface --resource-ids "$ENI" --traffic-type REJECT \
  --log-destination-type cloud-watch-logs --log-group-name /lab01/flow \
  --deliver-logs-permission-arn "arn:aws:iam::$ACCOUNT_ID:role/nimbus/nimbus-flowlogs" >/dev/null && echo "flow logs on $ENI (REJECT only)"
echo "Instance $ID ($TYPE) running at $IP. Allow about 4 minutes for the Docker build, then open: https://$IP:8443"
echo "The certificate is self signed. Compare its fingerprint with the one the server printed to its console:"
echo "  aws ec2 get-console-output --instance-id $ID --latest --output text | grep -i 'sha256 fingerprint'"
