"""Static checks on the IAM policy templates: least privilege is enforced by tests, not by hope."""
import glob, json, os, re
import pytest
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
POL = f"{ROOT}/bootstrap/policies"
FILES = sorted(glob.glob(f"{POL}/*.json"))

def load(name): return json.load(open(f"{POL}/{name}.json"))
def stmts(name):
    s = load(name)["Statement"]; return s if isinstance(s, list) else [s]
def as_list(x): return x if isinstance(x, list) else [x]
def render(name):
    return re.sub(r"__[A-Z_]+__", "X", open(f"{POL}/{name}.json").read())

@pytest.mark.parametrize("f", FILES, ids=os.path.basename)
def test_valid_json_and_version(f):
    d = json.load(open(f)); assert d["Version"] == "2012-10-17" and d["Statement"]

@pytest.mark.parametrize("f", FILES, ids=os.path.basename)
def test_no_statement_mixes_action_and_notaction(f):
    for s in json.load(open(f))["Statement"]:
        assert not ("Action" in s and "NotAction" in s), s.get("Sid")
        assert not ("Resource" in s and "NotResource" in s), s.get("Sid")

@pytest.mark.parametrize("f", FILES, ids=os.path.basename)
def test_every_statement_has_sid_and_effect(f):
    for s in json.load(open(f))["Statement"]:
        if "Sid" in s: assert re.fullmatch(r"[A-Za-z0-9]+", s["Sid"])
        assert s["Effect"] in ("Allow", "Deny")

@pytest.mark.parametrize("name", ["svc-web", "svc-onboarding", "svc-offboarding", "svc-dashboard", "ec2-instance-role"])
def test_service_roles_never_allow_wildcard_actions(name):
    for s in stmts(name):
        if s["Effect"] == "Allow":
            for a in as_list(s["Action"]):
                assert a != "*" and not a.endswith(":*"), (name, a)

@pytest.mark.parametrize("name", ["svc-web", "svc-onboarding", "svc-offboarding", "svc-dashboard", "ec2-instance-role"])
def test_service_roles_have_no_iam_privilege_escalation_actions(name):
    banned = {"iam:CreateAccessKey", "iam:PutUserPolicy", "iam:AttachRolePolicy", "iam:CreateRole", "iam:UpdateAssumeRolePolicy",
              "iam:PassRole", "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:AttachGroupPolicy", "iam:DeleteUser"}
    for s in stmts(name):
        assert not banned & set(as_list(s["Action"])), (name, s["Sid"])

@pytest.mark.parametrize("name", ["svc-web", "svc-onboarding", "svc-offboarding", "svc-dashboard"])
def test_star_resource_only_for_list_actions(name):
    for s in stmts(name):
        if s["Resource"] == "*":
            assert all(a.startswith(("iam:List", "iam:Get")) for a in as_list(s["Action"])), s["Sid"]

@pytest.mark.parametrize("name", ["svc-onboarding", "svc-offboarding"])
def test_attach_policy_is_pinned_to_one_policy_arn(name):
    att = [s for s in stmts(name) if "iam:AttachUserPolicy" in as_list(s["Action"])]
    assert len(att) == 1
    arn = att[0]["Condition"]["ArnEquals"]["iam:PolicyARN"]
    assert arn.endswith("Nimbus-RequireMFA" if name == "svc-onboarding" else "Nimbus-DenyAll")

@pytest.mark.parametrize("name", ["svc-onboarding", "svc-offboarding", "svc-dashboard"])
def test_iam_user_resources_are_fenced_to_nimbus_path(name):
    for s in stmts(name):
        if any(a.startswith("iam:") for a in as_list(s["Action"])) and s["Resource"] != "*":
            for r in as_list(s["Resource"]):
                assert "/nimbus/" in r, (name, r)

def test_web_role_has_no_iam_or_s3():
    for s in stmts("svc-web"):
        assert all(a.startswith("secretsmanager:") for a in as_list(s["Action"]))

def test_dashboard_role_is_read_only():
    for s in stmts("svc-dashboard"):
        for a in as_list(s["Action"]):
            assert re.match(r"(iam:(Get|List)|s3:(GetObject|ListBucket)|secretsmanager:GetSecretValue)", a), a

def test_only_onboarding_can_create_users_or_passwords():
    for name in ("svc-web", "svc-offboarding", "svc-dashboard", "ec2-instance-role"):
        acts = {a for s in stmts(name) for a in as_list(s["Action"])}
        assert not {"iam:CreateUser", "iam:CreateLoginProfile"} & acts, name

def test_secrets_scoped_by_name_prefix():
    for name in ("svc-web", "svc-onboarding", "svc-offboarding", "svc-dashboard"):
        for s in stmts(name):
            if "secretsmanager:GetSecretValue" in as_list(s["Action"]):
                assert all(":secret:nimbus/" in r for r in as_list(s["Resource"]))

def test_ec2_instance_role_can_only_assume_service_roles_and_write_app_logs():
    a, b = stmts("ec2-instance-role")
    assert a["Action"] == "sts:AssumeRole" and a["Resource"].endswith("role/nimbus/nimbus-*-svc")
    assert set(as_list(b["Action"])) == {"logs:CreateLogStream", "logs:PutLogEvents"}
    assert b["Resource"].endswith("log-group:/lab01/app:*")

def test_flowlogs_role_writes_only_the_flow_log_group():
    (s,) = stmts("flowlogs-role"); assert s["Resource"].endswith("log-group:/lab01/flow:*")
    (t,) = stmts("flowlogs-trust"); assert t["Principal"]["Service"] == "vpc-flow-logs.amazonaws.com"

def test_s3_endpoint_policy_names_only_our_bucket():
    (s,) = stmts("s3-endpoint-policy")
    assert all("__BUCKET__" in r for r in as_list(s["Resource"])) and "s3:DeleteObject" not in as_list(s["Action"])

def test_bucket_policies_deny_old_tls_on_data_bucket():
    assert "s3:TlsVersion" in open(f"{POL}/data-bucket-policy.json").read()

def test_cloudtrail_write_is_pinned_to_our_trail():
    s = {x["Sid"]: x for x in stmts("log-bucket-policy")}
    assert s["CloudTrailWrite"]["Condition"]["StringEquals"]["aws:SourceArn"].endswith("trail/lab01-trail")

def test_service_role_trust_names_exact_instance_role_not_account_root():
    (s,) = stmts("svc-trust")
    p = s["Principal"]["AWS"]; assert p.endswith("role/nimbus/nimbus-ec2-instance") and not p.endswith(":root")

def test_require_mfa_policy_shape():
    deny = [s for s in stmts("Nimbus-RequireMFA") if s["Effect"] == "Deny"]
    assert len(deny) == 1 and "NotAction" in deny[0]
    assert deny[0]["Condition"] == {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}
    na = deny[0]["NotAction"]
    for needed in ("iam:EnableMFADevice", "iam:CreateVirtualMFADevice", "iam:ChangePassword", "sts:GetSessionToken"):
        assert needed in na
    allow = [s for s in stmts("Nimbus-RequireMFA") if s["Effect"] == "Allow" and s["Resource"] != "*"]
    assert all("${aws:username}" in r for s in allow for r in as_list(s["Resource"]))   # self-service only

def test_deny_all_policy():
    (s,) = stmts("Nimbus-DenyAll"); assert (s["Effect"], s["Action"], s["Resource"]) == ("Deny", "*", "*")

def test_team_policies_do_not_lock_out_mfa_enrollment():
    """The slide 3.6 / 4.2 trap: a Deny with NotAction would also block MFA setup."""
    for name in ("TechTeam-DevScoped", "BusinessTeam-ReadOnly", "SecurityTeam-IAMAudit"):
        for s in stmts(name):
            if s["Effect"] == "Deny":
                assert "NotAction" not in s, name
                acts = set(as_list(s["Action"]))
                assert not any(a in acts for a in ("iam:*", "iam:Create*", "iam:Put*", "iam:CreateVirtualMFADevice")), name

def test_tech_team_denied_billing_and_escalation_but_no_iam_allow():
    t = stmts("TechTeam-DevScoped")
    allow_actions = {a for s in t if s["Effect"] == "Allow" for a in as_list(s["Action"])}
    assert not any(a.startswith("iam:") for a in allow_actions)
    deny_actions = {a for s in t if s["Effect"] == "Deny" for a in as_list(s["Action"])}
    assert {"billing:*", "iam:AttachUserPolicy", "iam:PassRole"} <= deny_actions

def test_business_team_has_no_data_plane_allow():
    for s in stmts("BusinessTeam-ReadOnly"):
        if s["Effect"] == "Allow":
            assert all(a.split(":")[0] in ("ce", "budgets", "cloudwatch", "quicksight") for a in as_list(s["Action"]))

def test_security_team_cannot_read_data_or_secrets():
    d = [s for s in stmts("SecurityTeam-IAMAudit") if s["Effect"] == "Deny"][0]
    assert {"s3:GetObject", "secretsmanager:GetSecretValue"} <= set(as_list(d["Action"]))

@pytest.mark.parametrize("name", [os.path.basename(f)[:-5] for f in FILES])
def test_placeholders_are_only_the_known_ones(name):
    assert set(re.findall(r"__[A-Z_]+__", open(f"{POL}/{name}.json").read())) <= {"__ACCOUNT_ID__", "__BUCKET__", "__LOGBUCKET__", "__REGION__", "__TOPIC_ARN__"}
