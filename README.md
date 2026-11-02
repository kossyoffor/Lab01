# Lab01: Nimbus Identity Console (IAM on the AWS free tier)

Four Flask microservices on one free-tier EC2 instance manage the IAM lifecycle of a 10-person
company (scales to 100). S3 holds the registry and audit log, Secrets Manager holds credentials,
and one IAM role per service enforces least privilege.

    web (8443 https, your IP only) -> onboarding (5001) -> IAM + S3
                       -> offboarding (5002) -> IAM + S3
                       -> dashboard (5003)   -> IAM + S3 (read only)
    secrets: nimbus/internal-token, nimbus/web-login

## Layout
    common/      shared library (assume-role session, secrets, S3 registry, audit)
    services/    web, onboarding, offboarding, dashboard
    bootstrap/   00 preflight, 01 groups+policies, 02 buckets+secrets+log groups, 03 roles, 04 detection
                 (CloudTrail, SNS, EventBridge), 05 EC2 + network controls, 06 usage, 07 rotate token,
                 08 investigate, 99 cleanup;  policies/ (IAM + bucket policies), config/ (lifecycle, event patterns)
    scripts/     create_repo.sh, seed_employees.py
    tests/       unit/ (in-process AWS mock) and integration/ (HTTP + real scripts against a mock server)

## Security measures (all free tier)
    Identity   groups, MFA guard, per service roles, kill switch, drift detection
    Network    HTTPS only console, no SSH, egress limited to 80/443, S3 gateway endpoint with policy,
               REJECT flow logs, security headers, login lockout
    Data       TLS only bucket policies, versioning, lifecycle expiry, S3 access logs, token rotation
    Logging    CloudTrail, EventBridge email alerts, structured JSON logs in CloudWatch, investigate script

## Tests (no AWS account, no cost)
    ./run_tests.sh unit
    ./run_tests.sh integration
    ./run_tests.sh            # both

## Git repository
    ./scripts/create_repo.sh                                   # local repo named after this folder (Lab01)
    GITHUB_USER=you GITHUB_TOKEN=... ./scripts/create_repo.sh  # also creates a public GitHub repo and pushes

Nothing secret is stored in this repository.
