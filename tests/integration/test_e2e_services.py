"""End-to-end test of all four services against a local MOCK of AWS (moto).
Run:  pytest -q tests      (no AWS account or cost involved)"""
import json, os, subprocess, sys, threading, time, importlib
import boto3, pytest, requests
from werkzeug.serving import make_server

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MOTO = "http://127.0.0.1:5999"
ACCT = "123456789012"


@pytest.fixture(scope="session", autouse=True)
def stack():
    os.environ.update(AWS_ENDPOINT_URL=MOTO)
    moto = subprocess.Popen([sys.executable, "-m", "moto.server", "-p", "5999"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try: requests.get(MOTO); break
        except Exception: time.sleep(.2)
    kw = dict(region_name="us-east-2")
    iam, s3, sm = boto3.client("iam", **kw), boto3.client("s3", **kw), boto3.client("secretsmanager", **kw)
    s3.create_bucket(Bucket="nimbus-test", CreateBucketConfiguration={"LocationConstraint": "us-east-2"})
    for g in ("TechTeam", "BusinessTeam", "SecurityTeam"):
        iam.create_group(GroupName=g, Path="/nimbus/")
    for n in ("Nimbus-RequireMFA", "Nimbus-DenyAll"):
        iam.create_policy(PolicyName=n, Path="/nimbus/", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}))
    sm.create_secret(Name="nimbus/internal-token", SecretString="tok-123")
    sm.create_secret(Name="nimbus/web-login", SecretString=json.dumps(
        {"flask_secret_key": "k" * 32, "admin_username": "admin", "admin_password": "pw-admin"}))
    servers = {}
    for name, port in (("onboarding", 5001), ("offboarding", 5002), ("dashboard", 5003), ("web", 8080)):
        os.environ.update(ONBOARD_URL="http://127.0.0.1:5001", OFFBOARD_URL="http://127.0.0.1:5002",
                          DASHBOARD_URL="http://127.0.0.1:5003")
        spec = importlib.util.spec_from_file_location(f"svc_{name}", f"{ROOT}/services/{name}/app.py")
        mod = importlib.util.module_from_spec(spec); sys.modules[f"svc_{name}"] = mod; spec.loader.exec_module(mod)
        srv = make_server("127.0.0.1", port, mod.app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start(); servers[name] = srv
    yield
    for s in servers.values(): s.shutdown()
    moto.terminate(); os.environ.pop("AWS_ENDPOINT_URL", None)


H = {"X-Internal-Token": "tok-123"}
def post(port, path, **j): return requests.post(f"http://127.0.0.1:{port}{path}", json=j, headers=H)
def dash(): return {e["username"]: e for e in requests.get("http://127.0.0.1:5003/api/employees?refresh=1", headers=H).json()["employees"]}


def test_auth_required_between_services():
    assert requests.post("http://127.0.0.1:5001/onboard", json={}).status_code == 401
    assert requests.get("http://127.0.0.1:5003/api/employees", headers={"X-Internal-Token": "bad"}).status_code == 401


def test_validation():
    assert post(5001, "/onboard", username="Bad Name", persona="developer", full_name="x", email="a@b.c").status_code == 400
    assert post(5001, "/onboard", username="bob", persona="wizard", full_name="x", email="a@b.c").status_code == 400


def test_onboard_creates_everything():
    r = post(5001, "/onboard", username="alice", persona="developer", full_name="Alice A", email="alice@nimbus.io")
    assert r.status_code == 201, r.text
    body = r.json(); assert body["group"] == "TechTeam" and len(body["temp_password"]) == 20
    iam = boto3.client("iam")
    assert [g["GroupName"] for g in iam.list_groups_for_user(UserName="alice")["Groups"]] == ["TechTeam"]
    assert iam.list_attached_user_policies(UserName="alice")["AttachedPolicies"][0]["PolicyName"] == "Nimbus-RequireMFA"
    assert iam.get_login_profile(UserName="alice")["LoginProfile"]["UserName"] == "alice"
    assert {t["Key"] for t in iam.list_user_tags(UserName="alice")["Tags"]} >= {"persona", "onboarded", "mfa-deadline"}
    assert post(5001, "/onboard", username="alice", persona="developer", full_name="x", email="a@b.c").status_code == 409
    # password must never be persisted
    reg = boto3.client("s3").get_object(Bucket="nimbus-test", Key="registry/alice.json")["Body"].read().decode()
    assert body["temp_password"] not in reg
    assert dash()["alice"]["health"] == "MFA PENDING"
def test_offboard_closes_access_and_dashboard_detects_drift():
    iam = boto3.client("iam")
    post(5001, "/onboard", username="carol", persona="finance", full_name="Carol C", email="c@nimbus.io")
    key = iam.create_access_key(UserName="carol")["AccessKey"]["AccessKeyId"]
    assert dash()["carol"]["iam"]["active_keys"] == 1
    r = post(5002, "/offboard", username="carol", reason="resigned"); assert r.status_code == 200, r.text
    assert iam.list_groups_for_user(UserName="carol")["Groups"] == []
    assert iam.list_access_keys(UserName="carol")["AccessKeyMetadata"][0]["Status"] == "Inactive"
    with pytest.raises(Exception): iam.get_login_profile(UserName="carol")
    assert dash()["carol"]["health"] == "CLOSED"
    assert post(5002, "/offboard", username="carol").status_code == 409
    # simulate someone re-enabling access behind the app's back -> DRIFT
    iam.update_access_key(UserName="carol", AccessKeyId=key, Status="Active")
    assert dash()["carol"]["health"] == "DRIFT"
    assert post(5002, "/offboard", username="ghost").status_code == 404


def test_untracked_user_flagged():
    boto3.client("iam").create_user(UserName="mallory", Path="/nimbus/")
    assert dash()["mallory"]["health"] == "UNTRACKED"


def test_audit_log_written():
    keys = [o["Key"] for o in boto3.client("s3").list_objects_v2(Bucket="nimbus-test", Prefix="audit/")["Contents"]]
    assert any("onboard-alice" in k for k in keys) and any("offboard-carol" in k for k in keys)


def test_web_pages_and_csrf():
    s = requests.Session(); base = "http://127.0.0.1:8080"
    assert s.get(base + "/dashboard", allow_redirects=False).status_code == 302
    assert "Invalid credentials" in s.post(base + "/login", data={"username": "admin", "password": "no"}).text
    assert s.post(base + "/login", data={"username": "admin", "password": "pw-admin"}).status_code == 200
    d = s.get(base + "/dashboard").text
    assert "Identity dashboard" in d, d[:300]
    assert "alice" in d and "DRIFT" in d and "UNTRACKED" in d
    on = s.get(base + "/onboard").text; import re
    csrf = re.search(r'name="csrf" value="([^"]+)"', on).group(1)
    assert s.post(base + "/onboard", data={"username": "dave", "persona": "devops"}).status_code == 400  # no CSRF
    r = s.post(base + "/onboard", data={"csrf": csrf, "username": "dave", "full_name": "Dave D",
                                        "email": "d@n.io", "persona": "devops", "console_access": "on"})
    assert "One-time console password" in r.text and "TechTeam" in r.text
    assert "dave" in s.get(base + "/offboard").text
    r = s.post(base + "/offboard", data={"csrf": csrf, "username": "dave", "reason": "test"}, allow_redirects=True)
    assert "Offboarded dave" in r.text
