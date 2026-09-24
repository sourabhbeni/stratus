"""Stratus CLI — audit an AWS account for common misconfigurations."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks import ec2 as ec2_checks
from .checks import iam as iam_checks
from .checks import logging as log_checks
from .checks import s3 as s3_checks
from . import report as report_mod


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="stratus",
        description="Audit an AWS account for common misconfigurations. "
                    "Only run against accounts you own or are authorized to assess.",
    )
    p.add_argument("command", choices=["audit"], help="audit: run all checks")
    p.add_argument("--profile", default=None, help="AWS profile name")
    p.add_argument("--region", default=None, help="AWS region (default: from config)")
    p.add_argument("-o", "--output", default="stratus-report.html", help="HTML report path")
    p.add_argument("--json", dest="json_out", default=None, help="Also write JSON results here")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def _session(profile, region):
    try:
        import boto3
        import botocore.exceptions
    except ImportError:
        print("error: boto3 is not installed — run: pip install -r requirements.txt", file=sys.stderr)
        raise SystemExit(2)
    try:
        sess = boto3.Session(profile_name=profile, region_name=region)
        # Fail fast if credentials are missing/invalid.
        sess.client("sts").get_caller_identity()
        return sess, botocore.exceptions
    except Exception as exc:
        print(f"error: AWS credentials not usable ({exc}).", file=sys.stderr)
        print("hint: run `aws configure` or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.", file=sys.stderr)
        raise SystemExit(2)


def main(argv=None) -> int:
    args = parse_args(argv)
    print(f"☁️  stratus {__version__} → audit")
    sess, botocore_exc = _session(args.profile, args.region)
    identity = sess.client("sts").get_caller_identity().get("Arn", "?")
    print(f"  identity: {identity}")

    suites = [
        ("S3", lambda: s3_checks.run(sess.client("s3"))),
        ("EC2", lambda: ec2_checks.run_ec2(sess.client("ec2"))),
        ("RDS", lambda: ec2_checks.run_rds(sess.client("rds"))),
        ("IAM", lambda: iam_checks.run(sess.client("iam"))),
        ("CloudTrail", lambda: log_checks.run(sess.client("cloudtrail"))),
    ]
    findings: list[dict] = []
    for name, fn in suites:
        print(f"  ▸ {name} …", flush=True)
        try:
            got = fn()
        except botocore_exc.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "?")
            print(f"    ! skipped ({code})")
            continue
        except Exception as exc:
            print(f"    ! skipped ({exc})")
            continue
        print(f"    {len(got)} findings")
        findings += got

    rep = report_mod.build_report(identity, findings)
    with open(args.output, "w") as f:
        f.write(report_mod.to_html(rep))
    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(report_mod.to_json(rep))

    n_high = rep["summary"]["high"]
    print(f"  ✓ {len(findings)} findings ({n_high} high)")
    print(f"  → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
