"""Helpers shared by all four services.

* aws_session()  - the container only holds the EC2 instance role; each service
                   then ASSUMES ITS OWN ROLE (sts:AssumeRole, deck slide 1.6).
* get_secret()   - reads from AWS Secrets Manager (nothing secret in the repo/image).
* registry/audit - JSON documents in S3 (the "database" of this lab).
* require_internal_token - service-to-service authentication.
"""
import functools, hmac, json, os, sys, threading, time, datetime as dt
import boto3
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.exceptions import ClientError
from botocore.session import get_session
from flask import jsonify, request

REGION = os.environ.get("AWS_REGION", "us-east-2")
BUCKET = os.environ.get("NIMBUS_BUCKET", "")
ROLE_NAME = os.environ.get("ROLE_NAME", "")
SKIP_ASSUME = os.environ.get("NIMBUS_SKIP_ASSUME") == "1"   # only for local tests
_CFG = Config(region_name=REGION, retries={"max_attempts": 5, "mode": "standard"})

_lock = threading.Lock()
_session = None
_account = None


def aws_session():
    """boto3 session that auto-refreshes short-lived credentials of this service's role."""
    global _session, _account
    with _lock:
        if _session is not None:
            return _session
        sts = boto3.client("sts", config=_CFG)
        _account = sts.get_caller_identity()["Account"]
        if SKIP_ASSUME or not ROLE_NAME:
            _session = boto3.Session(region_name=REGION)
            return _session
        arn = f"arn:aws:iam::{_account}:role/nimbus/{ROLE_NAME}"

        def refresh():
            c = sts.assume_role(RoleArn=arn, RoleSessionName=ROLE_NAME,
                                DurationSeconds=900)["Credentials"]
            exp = c["Expiration"]
            return {"access_key": c["AccessKeyId"], "secret_key": c["SecretAccessKey"],
                    "token": c["SessionToken"],
                    "expiry_time": exp.isoformat() if hasattr(exp, "isoformat") else str(exp)}

        bs = get_session()
        bs._credentials = RefreshableCredentials.create_from_metadata(
            metadata=refresh(), refresh_using=refresh, method="sts-assume-role")
        bs.set_config_variable("region", REGION)
        _session = boto3.Session(botocore_session=bs)
        return _session


def client(name):
    return aws_session().client(name, config=_CFG)


def account_id():
    aws_session()
    return _account


def whoami():
    return client("sts").get_caller_identity()["Arn"]


# ---------- structured logging (shipped to CloudWatch Logs by the Docker awslogs driver) ----------
SERVICE = os.environ.get("SERVICE_NAME", ROLE_NAME or "app")
SENSITIVE = ("password", "token", "secret", "key")


def log_event(event, **fields):
    """One JSON line on stdout. Never pass secrets: values of sensitive-looking keys are masked."""
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "service": SERVICE, "event": event}
    for k, v in fields.items():
        rec[k] = "***" if any(s in k.lower() for s in SENSITIVE) else v
    print(json.dumps(rec, default=str), file=sys.stdout, flush=True)


# ---------- Secrets Manager ----------
_secret_cache = {}
SECRET_TTL = 60          # seconds: short, so a rotated secret is picked up quickly


def get_secret(name, ttl=SECRET_TTL, stage="AWSCURRENT"):
    key = (name, stage)
    hit = _secret_cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    raw = client("secretsmanager").get_secret_value(SecretId=name, VersionStage=stage)["SecretString"]
    try:
        val = json.loads(raw)
    except ValueError:
        val = raw
    _secret_cache[key] = (time.time(), val)
    return val


def internal_token():
    return get_secret("nimbus/internal-token")


def _accepted_tokens(refresh=False):
    ttl = 0 if refresh else SECRET_TTL
    toks = [str(get_secret("nimbus/internal-token", ttl=ttl))]
    try:                                         # the previous version stays valid during a rotation
        toks.append(str(get_secret("nimbus/internal-token", ttl=ttl, stage="AWSPREVIOUS")))
    except ClientError:
        pass
    return toks


_last_refresh = [0.0]


def require_internal_token(fn):
    """Service-to-service auth. Accepts the current AND previous token version so that
    rotating the secret never causes an outage; unknown tokens are logged and rejected."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        supplied = request.headers.get("X-Internal-Token", "").encode()
        ok = any(hmac.compare_digest(supplied, t.encode()) for t in _accepted_tokens())
        if not ok and time.time() - _last_refresh[0] > 5:       # maybe our cache is stale: refresh once
            _last_refresh[0] = time.time()
            ok = any(hmac.compare_digest(supplied, t.encode()) for t in _accepted_tokens(refresh=True))
            if ok:
                log_event("internal_token_refreshed")
        if not ok:
            log_event("internal_auth_rejected", path=request.path, remote=request.remote_addr)
            return jsonify(error="unauthorized"), 401
        return fn(*a, **k)
    return wrapper


# ---------- S3 registry + audit log ----------
def now():
    return dt.datetime.now(dt.timezone.utc)


def _key(username):
    return f"registry/{username}.json"


def put_json(key, obj):
    client("s3").put_object(Bucket=BUCKET, Key=key, ContentType="application/json",
                            Body=json.dumps(obj, indent=2, default=str).encode())


def get_json(key):
    try:
        body = client("s3").get_object(Bucket=BUCKET, Key=key)["Body"].read()
        return json.loads(body)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        raise


def get_employee(username):
    return get_json(_key(username))


def put_employee(rec):
    put_json(_key(rec["username"]), rec)


def list_employees():
    s3 = client("s3")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix="registry/"):
        keys += [o["Key"] for o in page.get("Contents", []) if o["Key"].endswith(".json")]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(8) as ex:
        return [r for r in ex.map(get_json, keys) if r]


def audit(action, username, actor, detail=None):
    ts = now().strftime("%Y%m%dT%H%M%S%fZ")
    put_json(f"audit/{ts}-{action}-{username}.json",
             {"time": now().isoformat(), "action": action, "username": username,
              "actor": actor, "service_identity": whoami(), "detail": detail or {}})
