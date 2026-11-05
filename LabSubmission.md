# Lab 01 Submission: Nimbus Identity Console

**Student:** Kosisochukwu Offor  
**Course:** ITMS 564 – Cloud Computing Security  
**Date:** November 5, 2026  

## Part A: Run the Tests Locally

### Q1. Test as security controls
Security tests should run in the CI/CD pipeline before code is merged or deployed. In this lab, the tests verify that the launch script does not open SSH port 22 and that the onboarding service receives only the MFA guard instead of broad IAM permissions. This prevents later code changes from silently weakening those controls. However, the tests may not detect a stolen administrator credential or a policy that is technically valid but grants access to the wrong business user. Policy-as-code tools such as OPA or cfn-guard enforce organization rules, IAM Access Analyzer examines policies for security issues, and secret scanners detect credentials accidentally committed to the repository. Using these controls together provides stronger protection than relying on unit tests alone.


## Part B: IAM Groups and Policies
### Q2. Why Nimbus-RequireMFA uses BoolIfExists

`BoolIfExists` treats the MFA condition as false when the `aws:MultiFactorAuthPresent` key is either false or missing. This is important because requests made with long-term access keys may not include that context key. If the policy used only `Bool`, a request with the key missing might avoid the MFA denial. Therefore, `BoolIfExists` closes that gap while still allowing the limited actions required to enroll an MFA device.

### Q3. Why an explicit Deny is still useful
An IAM Allow grants only the listed actions, but other permissions could later come from another group, user policy or role. The explicit Deny in `TechTeam-DevScoped` overrides those additional Allows and prevents developers from performing restricted IAM actions. This provides a dependable security boundary even when the user’s permissions change later.

### Q4. Group membership as an escalation path
The most valuable group would be `SecurityTeam` because its policy permits IAM and CloudTrail auditing and allows members to create or update policies under `/nimbus/`. An attacker controlling the onboarding service could place a new account in this group and attempt to create a more permissive version of a Nimbus policy. A permissions boundary could limit the maximum permissions available to the new user, while a condition could restrict `iam:AddUserToGroup` to an approved group determined by the employee’s persona. An organization-level SCP could deny sensitive IAM policy changes for every member account, including local administrators. I would use the group-name condition for this service because it directly prevents the onboarding role from assigning unauthorized groups, supported by a permissions boundary as defense in depth.

## Part C: Buckets, Secrets and Data Protection
### Q5. Where the administrator password could have been exposed
Without Secrets Manager, the administrator password could have been stored in the source-code repository, where anyone with repository access or its Git history might recover it. It could also have been placed in EC2 user data or an environment file, where a compromised host or container could read it. A third possibility is command history or application logs, which are commonly copied, retained and viewed by multiple administrators. Secrets Manager is safer because the application retrieves the secret when needed and access can be controlled and audited through IAM and CloudTrail.

### Q6. TLS-only policy compared with Block Public Access
S3 Block Public Access prevents the bucket or its objects from being exposed publicly through bucket policies or ACLs. It does not require authorized users and services to use an encrypted connection. The TLS-only bucket policy denies requests made over plain HTTP and connections using TLS versions below the required level. Therefore, both controls are needed: one prevents public exposure, while the other protects data while it travels across the network.

### Q7. Customer-managed encryption keys
A customer-managed KMS key provides control over rotation, disabling, auditing and decryption permissions. Its key policy can separate key administrators from application roles that use the key, reducing the power of one compromised account. The disadvantages are additional cost and possible data loss or downtime caused by an incorrect or disabled key policy.

## Part D: One IAM Role per Microservice

### Q8. IAM simulator results
1. **AdministratorAccess:** The principal was `nimbus-onboarding-svc`, the action was `iam:AttachUserPolicy`, and the resource was user `/nimbus/alice`. The request supplied thAdministratorAccess policy ARN, so the condition allowing only `Nimbus-RequireMFA` failed and the result was `implicitDeny`.
2. **MFA guard:** The same principal, action and user were tested with the `Nimbus-RequireMFA` policy ARN. The condition matched the onboarding policy, so the result was `allowed`.
3. **User outside `/nimbus/`:** The principal attempted `iam:CreateLoginProfile` on `lab-user`. Because that resource was outside the permitted `/nimbus/` path, no Allow applied and the result was `implicitDeny`.

### Q9. Four containers on one host
The IMDS hop limit of 2 allows containers to reach the instance metadata service, and the shared instance role permits them to assume all four service roles. Therefore, one compromised container could try to assume another service’s role. Using one EC2 instance per service provides strong isolation but costs more, while ECS task roles provide strong isolation with moderate operational effort. Kubernetes pod identity also provides role separation but introduces the greatest management complexity, so ECS task roles would be the best production choice.

## Part E: Logging and Alerts
### Q10. Events monitored by the lab
The lab alerts on risky IAM changes, such as creating access keys or changing policies, and successful console sign-ins without MFA. These events may indicate persistence, privilege escalation or compromised credentials. Sending an immediate alert allows security personnel to respond faster than if the events were only stored for later review.

### Q11. Blind spots in detection
The rules could miss CreateLoginProfile, which gives an existing user console access, and DeactivateMFADevice, which weakens account security. An EventBridge pattern for the first action would be:

{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": ["CreateLoginProfile"]
  }
}

Adding too many individual events can create alert fatigue and cause analysts to overlook important warnings. GuardDuty reduces this problem by analyzing activity patterns, threat intelligence and unusual behavior instead of alerting on every API call.

## Part F: Launch the Hardened Server
### Q12. Why the server has no SSH
The server has no SSH port or key pair because administrators do not need direct operating-system access, removing a common attack path. Troubleshooting is performed through EC2 console output, CloudWatch container logs and the application health checks. If the server cannot be repaired, it can be terminated and recreated from the repository.

### Q13. Effect of egress filtering
Egress filtering prevents a compromised container from connecting to arbitrary outbound ports, which limits some command-and-control and data-exfiltration methods. It does not stop malicious traffic that uses the permitted HTTP or HTTPS ports, including access to allowed AWS APIs. Application permissions and monitoring are still required because network filtering alone cannot identify the purpose of encrypted traffic.

### Q14. Certificates and trust on first use
Comparing the self-signed certificate fingerprint protects against a man-in-the-middle attacker presenting a different certificate during the first connection. Users often skip this check because fingerprints are long and must be obtained through a trusted channel. In production, an ACM certificate behind a load balancer is automatically trusted and renewed, while a public certificate authority verifies control of the domain. HSTS forces browsers to use HTTPS, and certificate transparency logs help detect certificates issued incorrectly for the domain.

## Part H: Security Experiments
### Q15. Network security proofs
The HTTPS test and HSTS security header proved encryption in transit and prevented the use of plain HTTP. The closed-port probes, restricted security-group rule and private S3 gateway endpoint demonstrated a smaller network attack surface. The repeated failed-login test produced a 429 response, proving that the lockout control limits password guessing. The remaining browser security headers reduced risks such as framing and unsafe content loading.

### Q16. MFA policy decision
The request without MFA was denied because Nimbus-RequireMFA contains an explicit Deny when the condition key aws:MultiFactorAuthPresent is false or missing. When MFA was present, that Deny no longer applied, so Jennifer’s BusinessTeam permission allowed the same action. The condition key was aws:MultiFactorAuthPresent.

### Q17. Investigation of Mallory
CloudTrail showed that Kosi-Lab-user created Mallory through the CreateUser API call in us-east-1. I found this by running the investigation script and then querying CloudTrail directly. The S3 registry audit did not show the event because Mallory was created directly through AWS CLI instead of the Nimbus onboarding application.

### Q18. Replacing IAM users with single sign-on
With IAM Identity Center, individual IAM users, console passwords, access keys and the current MFA-enrollment workflow would become unnecessary. Permission sets and external identity-provider groups would replace the lab’s IAM groups and user policies. MFA, rapid access removal, least privilege, logging and drift detection would still matter, but they would be enforced through the identity provider and Identity Center. New risks would include compromise of the identity provider, incorrect group synchronization, stale assignments and stolen federated sessions.

### Q19. Safe token rotation
Token rotation is safe without a restart because the services temporarily accept both AWSCURRENT and AWSPREVIOUS and refresh their cached token when needed. This allows requests using the old token to continue while the new value spreads across the services. If only AWSCURRENT were accepted, services holding the old cached token would fail authentication and cause an outage.

### Q20. Controls in the incident drill
An MFA requirement on sensitive IAM actions could have prevented the attacker from creating the backdoor access key with only stolen credentials. Nimbus-DenyAll limited the incident after detection by immediately blocking James’s access during containment. I would also add a free IAM policy that denies iam:CreateAccessKey except for an approved administrative role.

### Q21. Mapping the drill to security frameworks
Using stolen AWS credentials maps to MITRE ATT&CK T1078.004, Valid Accounts: Cloud Accounts. Creating James’s backdoor key maps to T1098.001, Additional Cloud Credentials, while the rejected probes relate to T1046, Network Service Discovery. In NIST SP 800-53, MFA maps to IA-2, CloudTrail logging maps to AU-2, and offboarding with DenyAll maps to AC-2 and AC-6. The lab does not fully meet AU-9 because an administrator in the same account could delete the trail or log bucket; a separate protected log account would better protect the evidence.

## Part I: From 10 to 100 People
### Q22. Scaling limits and changes
1. Permissions: IAM groups work for 100 users, but larger growth can reach group and user limits. I would move to IAM Identity Center permission sets.

2. Registry: S3 works at this size, but listing thousands of employee objects on every refresh becomes slow. I would use DynamoDB with indexed and paginated queries.

3. Dashboard: Repeated IAM calls become slow as the user count grows. I would use the IAM credential report and a longer cache.

4. Service identity: Containers sharing one host can assume another service’s role. I would use ECS task roles to isolate each service.

5. Sign-in: A shared administrator password does not scale securely. I would replace it with SSO through IAM Identity Center.

6. Logging: More users create more CloudTrail events. I would centralize the logs in a separate account and connect them to a SIEM.


### Q23. Organization-level guardrails

I would protect CloudTrail, Nimbus-DenyAll and S3 Block Public Access with this SCP:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"],
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": ["iam:DeletePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
      "Resource": "arn:aws:iam::*:policy/nimbus/Nimbus-DenyAll"
    },
    {
      "Effect": "Deny",
      "Action": ["s3:PutBucketPublicAccessBlock", "s3:DeleteBucketPublicAccessBlock"],
      "Resource": "*"
    }
  ]
}

An SCP limits the maximum permissions in member accounts but does not grant access or directly control external principals using resource-based policies. It also does not restrict identities in the management account because that account controls the AWS Organization. Therefore, the management account requires strong MFA, limited access and no normal workloads.

## Part J: Clean Up
### Q24. Trusting the logs
CloudTrail digest files contain hashes and digital signatures that help prove the log files were not changed or deleted after delivery. Their integrity can be checked with the aws cloudtrail validate-logs command for the trail’s S3 location and time range. In this lab, an administrator could still stop the trail, change its configuration or delete the log bucket before evidence is reviewed. A separate log-archive account would restrict access, while S3 Object Lock and MFA Delete would make alteration or deletion much harder.


## References
Explore-question reference mapping: Q1 uses references 1–2; Q4 uses 3; Q7 uses 4; Q9 uses 5; Q11 uses 6; Q14 uses 7; Q18 uses 8; Q21 uses 9–10; Q23 uses 11; and Q24 uses 12.

1. AWS, IAM Access Analyzer Policy Validation: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html
2. AWS, CloudFormation Guard: https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html
3. AWS, Permissions Boundaries for IAM Entities: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
4. AWS, Key Policies in AWS KMS: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
5. AWS, IAM Roles for Amazon ECS Tasks: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
6. AWS, Amazon GuardDuty: https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html
7. AWS, AWS Certificate Manager: https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html
8. AWS, IAM Identity Center: https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html
9. MITRE ATT&CK, Additional Cloud Credentials: https://attack.mitre.org/techniques/T1098/001/
10. NIST, SP 800-53 Revision 5: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
11. AWS, Service Control Policies: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
12. AWS, Validating CloudTrail Log Integrity: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html









