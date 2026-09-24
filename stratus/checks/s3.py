"""S3 checks: public exposure, encryption, versioning."""

from __future__ import annotations

from . import finding


def run(s3) -> list[dict]:
    out: list[dict] = []
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        # Public access
        public = False
        try:
            pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            blocked = all(pab.get(k) for k in
                          ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        except Exception:
            blocked = False
        try:
            is_public = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {}).get("IsPublic", False)
        except Exception:
            is_public = False
        if is_public or not blocked:
            public = True
            out.append(finding(
                "high" if is_public else "medium", "S3", "public-access", name,
                f"Bucket may be publicly accessible{' (bucket policy is public)' if is_public else ''}",
                "Enable all four Public Access Block settings unless public access is intentional, "
                "and keep bucket policies least-privilege."))
        # Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
            encrypted = True
        except Exception:
            encrypted = False
        if not encrypted:
            out.append(finding("low", "S3", "encryption", name,
                               "No default encryption configured",
                               "Enable SSE-S3 or SSE-KMS default encryption."))
        # Versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name).get("Status")
        except Exception:
            versioning = None
        if versioning != "Enabled":
            out.append(finding("low", "S3", "versioning", name,
                               "Versioning not enabled",
                               "Versioning protects against accidental deletion and ransomware-style overwrites."))
    return out
