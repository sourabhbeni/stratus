"""Offline unit tests for stratus — AWS clients are faked, no credentials needed."""

import datetime as dt

from stratus.checks import ec2 as ec2_checks
from stratus.checks import iam as iam_checks
from stratus.checks import logging as log_checks
from stratus.checks import s3 as s3_checks
from stratus import report as report_mod


class FakeS3:
    def list_buckets(self):
        return {"Buckets": [{"Name": "public-bucket"}, {"Name": "locked-bucket"}]}

    def get_public_access_block(self, Bucket):
        if Bucket == "locked-bucket":
            return {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
        raise Exception("NoSuchPublicAccessBlockConfiguration")

    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": Bucket == "public-bucket"}}

    def get_bucket_encryption(self, Bucket):
        if Bucket == "locked-bucket":
            return {"ServerSideEncryptionConfiguration": {}}
        raise Exception("NoSuchEncryptionConfiguration")

    def get_bucket_versioning(self, Bucket):
        return {"Status": "Enabled" if Bucket == "locked-bucket" else "Suspended"}


def test_s3_flags_public_unencrypted_unversioned():
    findings = s3_checks.run(FakeS3())
    by_bucket = {}
    for f in findings:
        by_bucket.setdefault(f["resource"], []).append(f["check"])
    assert "public-access" in by_bucket["public-bucket"]
    assert any(f["severity"] == "high" for f in findings if f["resource"] == "public-bucket")
    assert "encryption" in by_bucket["public-bucket"]
    assert "versioning" in by_bucket["public-bucket"]
    assert by_bucket.get("locked-bucket", []) == []


class FakeEC2:
    def describe_security_groups(self):
        return {"SecurityGroups": [{
            "GroupId": "sg-open",
            "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
            }, {
                "IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": [],
            }],
        }]}

    def describe_volumes(self):
        return {"Volumes": [{"VolumeId": "vol-1", "Encrypted": False},
                            {"VolumeId": "vol-2", "Encrypted": True}]}


def test_ec2_open_ssh_and_unencrypted_volume():
    findings = ec2_checks.run_ec2(FakeEC2())
    assert any(f["severity"] == "high" and ":22" in f["title"] for f in findings)
    # 8080 restricted to 10.0.0.0/8 must NOT be flagged
    assert not any("8080" in f["title"] for f in findings)
    assert any(f["check"] == "ebs-encryption" and f["resource"] == "vol-1" for f in findings)
    assert not any(f["resource"] == "vol-2" for f in findings)


class FakeRDS:
    def describe_db_instances(self):
        return {"DBInstances": [{
            "DBInstanceIdentifier": "prod-db",
            "PubliclyAccessible": True,
            "StorageEncrypted": False,
            "BackupRetentionPeriod": 0,
        }]}


def test_rds_public_unencrypted_no_backup():
    findings = ec2_checks.run_rds(FakeRDS())
    checks = {f["check"] for f in findings}
    assert {"public-db", "rds-encryption", "rds-backup"} <= checks
    assert any(f["severity"] == "high" for f in findings if f["check"] == "public-db")


class FakeIAM:
    def list_users(self):
        return {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}

    def list_mfa_devices(self, UserName):
        return {"MFADevices": [] if UserName == "alice" else [{"SerialNumber": "x"}]}

    def list_access_keys(self, UserName):
        if UserName == "alice":
            old = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(days=120)
            return {"AccessKeyMetadata": [{"AccessKeyId": "AKIA12345678", "Status": "Active", "CreateDate": old}]}
        return {"AccessKeyMetadata": []}

    def list_attached_user_policies(self, UserName):
        if UserName == "bob":
            return {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
        return {"AttachedPolicies": []}

    def list_groups_for_user(self, UserName):
        return {"Groups": []}

    def get_account_password_policy(self):
        raise Exception("NoSuchEntity")


def test_iam_mfa_stale_key_admin_and_policy():
    findings = iam_checks.run(FakeIAM())
    assert any(f["check"] == "mfa" and f["resource"] == "alice" for f in findings)
    assert not any(f["check"] == "mfa" and f["resource"] == "bob" for f in findings)
    assert any(f["check"] == "stale-key" and "120 days" in f["title"] for f in findings)
    assert any(f["check"] == "admin-policy" and f["resource"] == "bob" for f in findings)
    assert any(f["check"] == "password-policy" for f in findings)


class FakeCT:
    def __init__(self, trails):
        self.trails = trails

    def describe_trails(self):
        return {"trailList": self.trails}

    def get_trail_status(self, Name):
        return {"IsLogging": True}


def test_cloudtrail_none_is_high():
    findings = log_checks.run(FakeCT([]))
    assert len(findings) == 1 and findings[0]["severity"] == "high"


def test_cloudtrail_single_region_no_validation():
    findings = log_checks.run(FakeCT([{
        "Name": "t", "TrailARN": "arn", "IsMultiRegionTrail": False,
        "LogFileValidationEnabled": False,
    }]))
    checks = {f["check"] for f in findings}
    assert {"single-region", "no-validation"} <= checks


def test_report_orders_by_severity():
    findings = [
        {"severity": "info", "service": "S3", "check": "c", "resource": "r", "title": "i", "detail": ""},
        {"severity": "high", "service": "S3", "check": "c", "resource": "r", "title": "h", "detail": ""},
    ]
    rep = report_mod.build_report("arn:aws:iam::123:user/x", findings)
    assert rep["findings"][0]["severity"] == "high"
    assert rep["summary"]["high"] == 1
    assert "Stratus report" in report_mod.to_html(rep)
