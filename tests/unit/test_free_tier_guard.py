"""Static guard rails: the lab must not be able to create anything outside the free tier."""
import glob, os, re, subprocess
import pytest
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPTS = sorted(glob.glob(f"{ROOT}/bootstrap/*.sh") + glob.glob(f"{ROOT}/scripts/*.sh") + [f"{ROOT}/run_tests.sh"])
def read(p): return open(os.path.join(ROOT, p)).read()
LAUNCH = read("bootstrap/05-launch-ec2.sh")
ALL_SH = "\n".join(open(p).read() for p in SCRIPTS if not p.endswith("99-cleanup.sh") and "00-preflight" not in p and "06-usage" not in p)

@pytest.mark.parametrize("p", SCRIPTS, ids=os.path.basename)
def test_script_syntax(p):
    assert subprocess.run(["bash", "-n", p]).returncode == 0

@pytest.mark.parametrize("p", SCRIPTS, ids=os.path.basename)
def test_script_is_executable(p):
    assert os.access(p, os.X_OK) or p.endswith("env.sh")

@pytest.mark.parametrize("forbidden", [
    "allocate-address", "create-nat-gateway", "create-load-balancer", "create-db-instance", "create-cluster",
    "kms create-key", "InterfaceEndpoint", "--vpc-endpoint-type Interface", "create-transit-gateway", "create-vpn", "create-file-system",
    "elasticache", "opensearch", "create-function", "dynamodb create-table", "create-volume", "create-snapshot"])
def test_no_paid_resource_is_ever_created(forbidden):
    assert forbidden not in ALL_SH

def test_exactly_one_instance_with_count_one():
    assert LAUNCH.count("run-instances") == 1 and "--count 1" in LAUNCH

def test_instance_type_must_be_aws_free_tier_eligible():
    assert "FreeTierEligible" in LAUNCH
    assert "t3.micro" in LAUNCH
    for big in ("t3.small", "t3.medium", "m5", "c5", "t3.large"):
        assert big not in LAUNCH

def test_root_volume_small_gp3_deleted_on_terminate():
    m = re.search(r"VolumeSize=(\d+),VolumeType=gp3,DeleteOnTermination=true", LAUNCH)
    assert m and int(m.group(1)) <= 30                         # free tier gives 30 GB of EBS

def test_refuses_second_running_instance():
    assert "already running" in LAUNCH and "exit 1" in LAUNCH

def test_auto_shutdown_terminates_instance():
    assert "AUTO_SHUTDOWN_HOURS" in LAUNCH and "instance-initiated-shutdown-behavior terminate" in LAUNCH
    assert "shutdown -h +__SHUTDOWN_MIN__" in read("bootstrap/user-data.sh")

def test_ports_open_only_to_my_ip():
    ing = [l for l in LAUNCH.splitlines() if "authorize-security-group-ingress" in l]
    assert ing and all("$MYIP" in l and "0.0.0.0/0" not in l for l in ing)
    assert "--port 8443" in LAUNCH and "--port 22" not in LAUNCH and "--port 8080" not in LAUNCH

def test_no_ssh_and_no_key_pair():
    assert "--key-name" not in LAUNCH and "create-key-pair" not in LAUNCH
    assert "sshd" not in read("bootstrap/user-data.sh")

def test_egress_is_filtered_to_80_and_443():
    assert "revoke-security-group-egress" in LAUNCH
    m = re.findall(r"authorize-security-group-egress.*?(?=\n[a-z#])", LAUNCH, re.S)[0]
    assert "FromPort=443" in m and "FromPort=80" in m and "FromPort=22" not in m

def test_s3_endpoint_is_free_gateway_type_with_policy():
    assert "--vpc-endpoint-type Gateway" in LAUNCH and "--policy-document" in LAUNCH and "--vpc-endpoint-type Interface" not in LAUNCH

def test_flow_logs_are_reject_only_on_one_interface():
    assert "--traffic-type REJECT" in LAUNCH and "--resource-type NetworkInterface" in LAUNCH and "--traffic-type ALL" not in LAUNCH

def test_one_trail_only_management_events():
    d = read("bootstrap/04-detection.sh")
    assert d.count("create-trail") == 1 and "put-event-selectors" not in d and "--is-multi-region-trail" not in d.replace("--no-is-multi-region-trail", "")

def test_log_groups_have_short_retention():
    s = read("bootstrap/02-storage-and-secrets.sh")
    assert "put-retention-policy" in s and "--retention-in-days 7" in s

def test_buckets_deny_plain_http_and_expire_logs():
    for f in ("data-bucket-policy", "log-bucket-policy"):
        assert '"aws:SecureTransport":"false"' in read(f"bootstrap/policies/{f}.json").replace(" ", "")
    import json
    assert json.loads(read("bootstrap/config/lifecycle-logs.json"))["Rules"][0]["Expiration"]["Days"] <= 30

def test_tls_enabled_on_ec2_and_cookie_secure():
    u = read("bootstrap/user-data.sh")
    assert "openssl req -x509" in u and "COOKIE_SECURE=1" in u and "WEB_PORT=8443" in u and "docker-compose.aws.yml" in u

def test_imds_v2_required_and_hop_limit_two():
    assert "HttpTokens=required" in LAUNCH and "HttpPutResponseHopLimit=2" in LAUNCH

def test_s3_bucket_is_private_encrypted_versioned():
    s = read("bootstrap/02-storage-and-secrets.sh")
    assert "BlockPublicAcls=true" in s and "RestrictPublicBuckets=true" in s
    assert "AES256" in s and "Status=Enabled" in s

def test_secrets_use_default_key_not_paid_cmk():
    s = read("bootstrap/02-storage-and-secrets.sh"); assert "--kms-key-id" not in s
    assert s.count("create-secret") == 2                        # the lab must stay at two secrets

def test_cleanup_deletes_every_billable_thing():
    c = read("bootstrap/99-cleanup.sh")
    for needle in ("terminate-instances", "delete-security-group", "delete-flow-logs", "delete-vpc-endpoints", "delete-trail", "delete-topic", "delete-rule", "delete-log-group", "delete-secret", "force-delete-without-recovery",
                   "delete-objects", "delete-bucket", "delete-role", "delete-policy", "delete-group", "delete-user"):
        assert needle in c, needle

def test_compose_publishes_only_web():
    import yaml
    d = yaml.safe_load(read("docker-compose.yml"))["services"]
    assert [n for n, s in d.items() if "ports" in s] == ["web"]

def test_aws_override_logs_every_service_to_cloudwatch():
    import yaml
    base = yaml.safe_load(read("docker-compose.yml"))["services"]; o = yaml.safe_load(read("docker-compose.aws.yml"))["services"]
    assert set(o) == set(base) and all(s["logging"]["driver"] == "awslogs" for s in o.values())

def test_user_data_contains_no_credentials():
    u = "\n".join(l for l in read("bootstrap/user-data.sh").splitlines() if not l.strip().startswith("#"))
    u = re.sub(r"metadata-token(-ttl-seconds)?|api/token", "", u, flags=re.I)   # IMDSv2 session token is not a credential
    assert not re.search(r"AKIA|SECRET|PASSWORD|TOKEN", u, re.I)

def test_repo_hygiene_files_ignored():
    g = read(".gitignore")
    for p in (".env", "*.pem", ".nimbus-state", "certs/"): assert p in g

def test_no_aws_keys_anywhere_in_repo():
    pat = re.compile(r"AKIA[0-9A-Z]{16}|BEGIN (RSA |EC )?PRIVATE KEY|ghp_[A-Za-z0-9]{30,}")
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in (".git", ".venv", "__pycache__", ".pytest_cache")]
        for f in fn:
            p = os.path.join(dp, f)
            if f.endswith((".pyc", ".pem")): continue
            assert not pat.search(open(p, errors="ignore").read()), p

def test_requirements_are_pinned():
    for line in read("requirements.txt").split():
        assert "==" in line, line
