"""Runs the REAL bootstrap scripts (01 to 04, 99) with the AWS CLI against a local mock AWS
server, then proves that a service can assume its own role and read its secret. No cost."""
import json, os, shutil, subprocess, sys, time, importlib
import boto3, pytest, requests

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PORT = 5998; URL = f"http://127.0.0.1:{PORT}"
pytestmark = pytest.mark.skipif(shutil.which("aws") is None, reason="AWS CLI not installed")


@pytest.fixture(scope="module")
def env():
    p = subprocess.Popen([sys.executable, "-m", "moto.server", "-p", str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try: requests.get(URL); break
        except Exception: time.sleep(.2)
    e = {**os.environ, "AWS_ENDPOINT_URL": URL, "AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t",
         "AWS_REGION": "us-east-2", "AWS_DEFAULT_REGION": "us-east-2", "AWS_PAGER": ""}
    yield e
    p.terminate()


def run(env, script, stdin=None):
    r = subprocess.run(["bash", f"{ROOT}/bootstrap/{script}"], env=env, input=stdin, capture_output=True, text=True, cwd=f"{ROOT}/bootstrap")
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def client(env, name):
    return boto3.client(name, endpoint_url=URL, region_name="us-east-2", aws_access_key_id="t", aws_secret_access_key="t")


def test_01_groups_and_policies_are_idempotent(env):
    run(env, "01-groups-and-policies.sh"); run(env, "01-groups-and-policies.sh")        # second run must not fail
    iam = client(env, "iam")
    assert {g["GroupName"] for g in iam.list_groups(PathPrefix="/nimbus/")["Groups"]} == {"TechTeam", "BusinessTeam", "SecurityTeam"}
    for g, p in (("TechTeam", "TechTeam-DevScoped"), ("BusinessTeam", "BusinessTeam-ReadOnly"), ("SecurityTeam", "SecurityTeam-IAMAudit")):
        assert [x["PolicyName"] for x in iam.list_attached_group_policies(GroupName=g)["AttachedPolicies"]] == [p]
    names = {p["PolicyName"] for p in iam.list_policies(Scope="Local", PathPrefix="/nimbus/")["Policies"]}
    assert {"Nimbus-RequireMFA", "Nimbus-DenyAll"} <= names


def test_02_storage_and_secrets(env):
    out = run(env, "02-storage-and-secrets.sh")
    assert "Console login -> user: admin" in out
    s3 = client(env, "s3"); b = "lab01-nimbus-123456789012"
    assert s3.get_bucket_versioning(Bucket=b)["Status"] == "Enabled"
    assert s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True
    sm = client(env, "secretsmanager")
    assert sorted(x["Name"] for x in sm.list_secrets()["SecretList"]) == ["nimbus/internal-token", "nimbus/web-login"]
    lb = "lab01-logs-123456789012"
    assert s3.get_public_access_block(Bucket=lb)["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] is True
    assert "SecureTransport" in s3.get_bucket_policy(Bucket=b)["Policy"] and "cloudtrail.amazonaws.com" in s3.get_bucket_policy(Bucket=lb)["Policy"]
    assert s3.get_bucket_lifecycle_configuration(Bucket=lb)["Rules"][0]["Expiration"]["Days"] == 30
    assert s3.get_bucket_logging(Bucket=b)["LoggingEnabled"]["TargetBucket"] == lb
    groups = {g["logGroupName"]: g for g in client(env, "logs").describe_log_groups(logGroupNamePrefix="/lab01/")["logGroups"]}
    assert set(groups) == {"/lab01/app", "/lab01/flow"} and all(g["retentionInDays"] == 7 for g in groups.values())
    assert "console login" not in run(env, "02-storage-and-secrets.sh").lower()           # re-run does not rotate or reprint the password


def test_03_roles_and_real_assume_role(env):
    run(env, "03-service-roles.sh")
    iam = client(env, "iam")
    roles = {r["RoleName"] for r in iam.list_roles(PathPrefix="/nimbus/")["Roles"]}
    assert roles == {"nimbus-ec2-instance", "nimbus-flowlogs", "nimbus-web-svc", "nimbus-onboarding-svc", "nimbus-offboarding-svc", "nimbus-dashboard-svc"}
    # Use the real AssumeRole code path of the services (no NIMBUS_SKIP_ASSUME).
    code = ("import sys; sys.path.insert(0, %r); from common import nimbus; "
            "print(nimbus.whoami()); print(nimbus.internal_token()[:3] != '')" % ROOT)
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                         env={**{k: v for k, v in env.items() if k != "NIMBUS_SKIP_ASSUME"}, "ROLE_NAME": "nimbus-onboarding-svc", "NIMBUS_BUCKET": "x"})
    assert out.returncode == 0, out.stderr
    assert "assumed-role/nimbus-onboarding-svc/" in out.stdout and "True" in out.stdout


def test_04_detection_creates_trail_rules_topic(env):
    env = {**env, "ALERT_EMAIL": "student@example.com"}
    run(env, "04-detection.sh"); run(env, "04-detection.sh")                              # idempotent
    ct = client(env, "cloudtrail")
    (tr,) = ct.describe_trails(trailNameList=["lab01-trail"])["trailList"]
    assert tr["S3BucketName"] == "lab01-logs-123456789012" and tr["LogFileValidationEnabled"] and not tr["IsMultiRegionTrail"]
    ev = boto3.client("events", endpoint_url=URL, region_name="us-east-1", aws_access_key_id="t", aws_secret_access_key="t")
    rules = {r["Name"]: r for r in ev.list_rules(NamePrefix="lab01-")["Rules"]}
    assert set(rules) == {"lab01-risky-iam", "lab01-signin-without-mfa"}
    assert "CreateAccessKey" in rules["lab01-risky-iam"]["EventPattern"] and "MFAUsed" in rules["lab01-signin-without-mfa"]["EventPattern"]
    tg = ev.list_targets_by_rule(Rule="lab01-risky-iam")["Targets"]
    assert len(tg) == 1 and "LAB01 SECURITY ALERT (lab01-risky-iam)" in tg[0]["InputTransformer"]["InputTemplate"]
    sns = boto3.client("sns", endpoint_url=URL, region_name="us-east-1", aws_access_key_id="t", aws_secret_access_key="t")
    assert [t["TopicArn"].split(":")[-1] for t in sns.list_topics()["Topics"]] == ["lab01-security-alerts"]
    assert subprocess.run(["bash", f"{ROOT}/bootstrap/04-detection.sh"], env={k: v for k, v in env.items() if k != "ALERT_EMAIL"},
                                           capture_output=True, text=True).returncode != 0   # refuses without an alert address


def test_07_rotate_token_keeps_previous_value(env):
    sm = client(env, "secretsmanager")
    before = sm.get_secret_value(SecretId="nimbus/internal-token")["SecretString"]
    run(env, "07-rotate-token.sh")
    assert sm.get_secret_value(SecretId="nimbus/internal-token")["SecretString"] != before
    assert sm.get_secret_value(SecretId="nimbus/internal-token", VersionStage="AWSPREVIOUS")["SecretString"] == before


def test_99_cleanup_removes_everything(env):
    iam = client(env, "iam")
    iam.create_user(UserName="tmp1", Path="/nimbus/")
    run(env, "99-cleanup.sh", stdin="yes\n")
    assert iam.list_users(PathPrefix="/nimbus/")["Users"] == []
    assert iam.list_roles(PathPrefix="/nimbus/")["Roles"] == []
    assert iam.list_groups(PathPrefix="/nimbus/")["Groups"] == []
    assert iam.list_policies(Scope="Local", PathPrefix="/nimbus/")["Policies"] == []
    assert client(env, "secretsmanager").list_secrets()["SecretList"] == []
    assert client(env, "s3").list_buckets()["Buckets"] == []
    assert client(env, "cloudtrail").describe_trails()["trailList"] == []
    assert client(env, "logs").describe_log_groups(logGroupNamePrefix="/lab01/")["logGroups"] == []
    ev = boto3.client("events", endpoint_url=URL, region_name="us-east-1", aws_access_key_id="t", aws_secret_access_key="t")
    assert ev.list_rules(NamePrefix="lab01-")["Rules"] == []
