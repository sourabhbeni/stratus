# ☁️ Stratus

[![ci](https://github.com/sourabhbeni/stratus/actions/workflows/ci.yml/badge.svg)](https://github.com/sourabhbeni/stratus/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![aws](https://img.shields.io/badge/AWS-boto3-orange)
![license](https://img.shields.io/badge/license-MIT-green)

**AWS misconfiguration scanner.** Audits your account for the mistakes that cause
real breaches — public S3 buckets, world-open security groups, missing MFA, stale
access keys, unencrypted storage, and blind spots in CloudTrail — then writes a
clean HTML report.

```
$ python -m stratus audit --profile default

☁️  stratus 0.1.0 → audit
  identity: arn:aws:iam::123456789012:user/saurabh
  ▸ S3 …
    2 findings
  ▸ EC2 …
    3 findings
  ▸ RDS …
    0 findings
  ▸ IAM …
    2 findings
  ▸ CloudTrail …
    1 findings
  ✓ 8 findings (2 high)
  → stratus-report.html
```

## Checks

| Service | Check | Severity |
|---|---|---|
| S3 | Bucket publicly accessible via policy or missing Public Access Block | High / Medium |
| S3 | No default encryption · versioning disabled | Low |
| EC2 | Security group open to `0.0.0.0/0` on all ports | High |
| EC2 | SSH / RDP open to the world | High |
| EC2 | Databases (MySQL, Postgres, Redis, …) open to the world | Medium |
| EC2 | Unencrypted EBS volumes | Medium |
| RDS | Publicly accessible instance | High |
| RDS | Unencrypted storage · backups disabled | Medium / Low |
| IAM | User without MFA | Medium |
| IAM | Active access key older than 90 days | Medium |
| IAM | `AdministratorAccess` attached | Medium |
| IAM | Weak or missing password policy | Low |
| CloudTrail | No trails configured | High |
| CloudTrail | Trail not logging · single-region · no log validation | High / Medium / Low |

Checks are inspired by the [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
but Stratus is not a compliance tool — it's a fast, opinionated first pass.

## Install

```bash
git clone https://github.com/sourabhbeni/stratus && cd stratus
pip install -r requirements.txt
aws configure   # needs an IAM user/role with read permissions
```

Minimum IAM permissions: `s3:ListAllMyBuckets` + `s3:Get*`, `ec2:Describe*`,
`rds:Describe*`, `iam:List*` + `iam:Get*`, `cloudtrail:Describe*` + `cloudtrail:Get*`.
Read-only — Stratus never modifies anything.

## Usage

```bash
# Audit the default profile
python -m stratus audit

# Specific profile / region, JSON output too
python -m stratus audit --profile prod --region us-west-2 --json out.json -o out.html
```

## Architecture

```
stratus/
├── cli.py            # arg parsing, orchestration, credential handling
├── checks/
│   ├── s3.py         # public access, encryption, versioning
│   ├── ec2.py        # security groups, EBS, RDS posture
│   ├── iam.py        # MFA, key rotation, admin policies, password policy
│   └── logging.py    # CloudTrail coverage
└── report.py         # JSON + self-contained HTML report
```

Each check module exposes `run(client) -> list[Finding]` and is independently
testable with faked clients — see `tests/`.

## Tests

```bash
pip install -r requirements.txt pytest && python -m pytest -q
```

All tests run offline with mocked AWS clients (no credentials needed).

## Ethics

Only assess accounts you **own** or are **explicitly authorized** to audit.
Stratus is read-only, but running it against someone else's account without
permission is still out of bounds.

## Roadmap

- [ ] CIS-mapped control IDs on each finding
- [ ] `--fail-on high` exit codes for CI pipelines
- [ ] Markdown / SARIF output
- [ ] AWS Config rule generation from findings

## License

MIT — see [LICENSE](LICENSE).
