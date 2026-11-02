#!/usr/bin/env bash
# Lab version of deck scripts 01 + 02. Idempotent. Creates the 3 groups, the 5 managed
# policies and attaches the three team policies.
source "$(dirname "$0")/env.sh"

for G in TechTeam BusinessTeam SecurityTeam; do
  aws iam get-group --group-name "$G" >/dev/null 2>&1 \
    || aws iam create-group --group-name "$G" --path /nimbus/ >/dev/null
  echo "group ready: /nimbus/$G"
done

mkpolicy() {  # mkpolicy <name>   (file policies/<name>.json)
  local arn="arn:aws:iam::$ACCOUNT_ID:policy/nimbus/$1"
  if aws iam get-policy --policy-arn "$arn" >/dev/null 2>&1; then
    # new version of an existing policy (max 5 versions: drop oldest non-default first)
    local old; old=$(aws iam list-policy-versions --policy-arn "$arn" \
      --query 'Versions[?IsDefaultVersion==`false`]|[-1].VersionId' --output text)
    [ "$old" != "None" ] && [ "$(aws iam list-policy-versions --policy-arn "$arn" --query 'length(Versions)')" -ge 5 ] \
      && aws iam delete-policy-version --policy-arn "$arn" --version-id "$old"
    render "$POL/$1.json" > /tmp/pol.json
    aws iam create-policy-version --policy-arn "$arn" --policy-document file:///tmp/pol.json --set-as-default >/dev/null
  else
    render "$POL/$1.json" > /tmp/pol.json
    aws iam create-policy --policy-name "$1" --path /nimbus/ --policy-document file:///tmp/pol.json >/dev/null
  fi
  echo "policy ready: $arn"
}
for P in Nimbus-RequireMFA Nimbus-DenyAll TechTeam-DevScoped BusinessTeam-ReadOnly SecurityTeam-IAMAudit; do mkpolicy "$P"; done

for pair in TechTeam:TechTeam-DevScoped BusinessTeam:BusinessTeam-ReadOnly SecurityTeam:SecurityTeam-IAMAudit; do
  aws iam attach-group-policy --group-name "${pair%%:*}" --policy-arn "arn:aws:iam::$ACCOUNT_ID:policy/nimbus/${pair##*:}"
  echo "attached ${pair##*:} -> ${pair%%:*}"
done
