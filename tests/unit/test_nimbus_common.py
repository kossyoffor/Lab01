import json, time
import boto3, pytest
from flask import Flask
from tests.unit.conftest import HDR

def test_get_secret_json_and_plain(aws):
    n = aws["nimbus"]
    assert n.get_secret("nimbus/internal-token") == "unit-token"
    assert n.get_secret("nimbus/web-login")["admin_username"] == "admin"

def test_get_secret_is_cached(aws):
    n = aws["nimbus"]; n.get_secret("nimbus/internal-token")
    aws["sm"].put_secret_value(SecretId="nimbus/internal-token", SecretString="changed")
    assert n.get_secret("nimbus/internal-token") == "unit-token"           # served from cache
    assert n.get_secret("nimbus/internal-token", ttl=0) == "changed"        # ttl expired -> refetch

def test_require_internal_token_decorator(aws):
    n = aws["nimbus"]; app = Flask(__name__)
    @app.get("/x")
    @n.require_internal_token
    def x(): return "ok"
    c = app.test_client()
    assert c.get("/x").status_code == 401
    assert c.get("/x", headers={"X-Internal-Token": "nope"}).status_code == 401
    assert c.get("/x", headers=HDR).status_code == 200

def test_registry_roundtrip_and_missing(aws):
    n = aws["nimbus"]
    assert n.get_employee("ghost") is None
    n.put_employee({"username": "a1", "status": "active"}); n.put_employee({"username": "b2", "status": "active"})
    assert n.get_employee("a1")["status"] == "active"
    assert sorted(r["username"] for r in n.list_employees()) == ["a1", "b2"]

def test_list_employees_handles_more_than_one_page(aws):
    n = aws["nimbus"]
    for i in range(1100):                                                   # > 1000 = 2 S3 list pages
        aws["s3"].put_object(Bucket="nimbus-test", Key=f"registry/u{i:04d}.json", Body=json.dumps({"username": f"u{i:04d}"}))
    assert len(n.list_employees()) == 1100

def test_audit_record_has_actor_and_identity(aws):
    aws["nimbus"].audit("onboard", "alice", "admin", {"k": 1})
    keys = [o["Key"] for o in aws["s3"].list_objects_v2(Bucket="nimbus-test", Prefix="audit/")["Contents"]]
    assert len(keys) == 1 and keys[0].endswith("-onboard-alice.json")
    rec = json.loads(aws["s3"].get_object(Bucket="nimbus-test", Key=keys[0])["Body"].read())
    assert rec["actor"] == "admin" and rec["detail"] == {"k": 1} and rec["service_identity"].startswith("arn:aws:")


# ---- logging and token rotation (data and logging controls) ----
def test_log_event_is_json_and_masks_sensitive_fields(aws, capsys):
    aws["nimbus"].log_event("demo", username="alice", temp_password="hunter2", api_token="abc", secret_key="zzz")
    line = capsys.readouterr().out.strip()
    rec = json.loads(line)
    assert rec["event"] == "demo" and rec["username"] == "alice" and "ts" in rec
    assert rec["temp_password"] == rec["api_token"] == rec["secret_key"] == "***"
    assert "hunter2" not in line

def test_onboarding_never_logs_the_password(aws, onboarding, capsys):
    from tests.unit.conftest import HDR
    body = onboarding.post("/onboard", json={"username": "alice", "full_name": "A", "email": "a@x.io", "persona": "developer"}, headers=HDR).get_json()
    out = capsys.readouterr().out
    assert body["temp_password"] not in out and '"event": "onboarded"' in out

def _call_protected(aws, token):
    n = aws["nimbus"]; app = Flask(f"t{time.time_ns()}")
    @app.get("/x")
    @n.require_internal_token
    def x(): return "ok"
    return app.test_client().get("/x", headers={"X-Internal-Token": token}).status_code

def test_rotation_previous_token_still_works_then_expires(aws):
    n = aws["nimbus"]; n._last_refresh[0] = 0
    assert _call_protected(aws, "unit-token") == 200
    aws["sm"].put_secret_value(SecretId="nimbus/internal-token", SecretString="rotated-1")   # rotation 1
    n._secret_cache.clear(); n._last_refresh[0] = 0
    assert _call_protected(aws, "rotated-1") == 200          # new token accepted
    n._secret_cache.clear(); n._last_refresh[0] = 0
    assert _call_protected(aws, "unit-token") == 200         # previous version still accepted (grace)
    aws["sm"].put_secret_value(SecretId="nimbus/internal-token", SecretString="rotated-2")   # rotation 2
    n._secret_cache.clear(); n._last_refresh[0] = 0
    assert _call_protected(aws, "unit-token") == 401         # two rotations ago: rejected

def test_stale_cache_is_refreshed_once_on_mismatch(aws, capsys):
    n = aws["nimbus"]; n._last_refresh[0] = 0
    assert _call_protected(aws, "unit-token") == 200         # fills the cache
    aws["sm"].put_secret_value(SecretId="nimbus/internal-token", SecretString="fresh")
    n._last_refresh[0] = 0
    assert _call_protected(aws, "fresh") == 200              # cache was stale, refreshed on demand
    assert "internal_token_refreshed" in capsys.readouterr().out

def test_rejected_calls_are_logged(aws, capsys):
    aws["nimbus"]._last_refresh[0] = 0
    assert _call_protected(aws, "wrong") == 401
    assert "internal_auth_rejected" in capsys.readouterr().out

def test_secret_ttl_is_short():
    from common import nimbus
    assert nimbus.SECRET_TTL <= 60
