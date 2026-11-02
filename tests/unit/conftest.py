"""Unit-test fixtures: an in-process mock of IAM/S3/Secrets Manager (moto.mock_aws)."""
import importlib.util, json, os, sys
import boto3, pytest
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOKEN = "unit-token"
HDR = {"X-Internal-Token": TOKEN}


@pytest.fixture
def aws():
    """Fresh fake AWS account with groups, the two guard policies, bucket and secrets."""
    with mock_aws():
        from common import nimbus
        nimbus._session = None; nimbus._account = None; nimbus._secret_cache.clear()
        iam, s3, sm = boto3.client("iam"), boto3.client("s3"), boto3.client("secretsmanager")
        s3.create_bucket(Bucket="nimbus-test", CreateBucketConfiguration={"LocationConstraint": "us-east-2"})
        for g in ("TechTeam", "BusinessTeam", "SecurityTeam"):
            iam.create_group(GroupName=g, Path="/nimbus/")
        deny = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
        for p in ("Nimbus-RequireMFA", "Nimbus-DenyAll"):
            iam.create_policy(PolicyName=p, Path="/nimbus/", PolicyDocument=deny)
        sm.create_secret(Name="nimbus/internal-token", SecretString=TOKEN)
        sm.create_secret(Name="nimbus/web-login", SecretString=json.dumps(
            {"flask_secret_key": "k" * 32, "admin_username": "admin", "admin_password": "pw"}))
        yield {"iam": iam, "s3": s3, "sm": sm, "nimbus": nimbus}


def load_service(name):
    """Import services/<name>/app.py under its own module name (must be called inside `aws`)."""
    key = f"unit_svc_{name}"
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, f"{ROOT}/services/{name}/app.py")
    mod = importlib.util.module_from_spec(spec); sys.modules[key] = mod; spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def onboarding(aws):  return load_service("onboarding").app.test_client()
@pytest.fixture
def offboarding(aws): return load_service("offboarding").app.test_client()
@pytest.fixture
def dashboard(aws):
    m = load_service("dashboard"); m._cache.update(t=0, data=None); return m.app.test_client()
@pytest.fixture
def web(aws):         return load_service("web").app.test_client()
