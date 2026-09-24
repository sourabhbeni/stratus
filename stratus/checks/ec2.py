"""EC2 / RDS checks: world-open security groups, unencrypted volumes, public databases."""

from __future__ import annotations

from . import finding, is_open_to_world, ports_covered

#: Ports that should never be open to 0.0.0.0/0.
RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
               6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 5601: "Kibana"}


def run_ec2(ec2) -> list[dict]:
    out: list[dict] = []
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        sg_id = sg["GroupId"]
        for perm in sg.get("IpPermissions", []):
            if not is_open_to_world(perm):
                continue
            covered = ports_covered(perm)
            if covered is None:
                out.append(finding("high", "EC2", "open-sg", sg_id,
                                   "Security group open to the world on ALL ports",
                                   "0.0.0.0/0 with IpProtocol -1 exposes every port. Scope to specific ports/CIDRs."))
                continue
            risky = sorted(covered & RISKY_PORTS.keys())
            for port in risky:
                out.append(finding(
                    "high" if port in (22, 3389) else "medium", "EC2", "open-sg", sg_id,
                    f"{RISKY_PORTS[port]} (:{port}) open to 0.0.0.0/0",
                    "Restrict to known IPs or a bastion/VPN; never the whole internet."))
    for vol in ec2.describe_volumes().get("Volumes", []):
        if not vol.get("Encrypted"):
            out.append(finding("medium", "EC2", "ebs-encryption", vol["VolumeId"],
                               "EBS volume is unencrypted",
                               "Enable encryption by default in the region settings."))
    return out


def run_rds(rds) -> list[dict]:
    out: list[dict] = []
    for db in rds.describe_db_instances().get("DBInstances", []):
        name = db["DBInstanceIdentifier"]
        if db.get("PubliclyAccessible"):
            out.append(finding("high", "RDS", "public-db", name,
                               "RDS instance is publicly accessible",
                               "Databases should live in private subnets; use a bastion or VPN for access."))
        if not db.get("StorageEncrypted"):
            out.append(finding("medium", "RDS", "rds-encryption", name,
                               "RDS storage is unencrypted",
                               "Enable storage encryption (KMS) at creation time."))
        if not db.get("BackupRetentionPeriod"):
            out.append(finding("low", "RDS", "rds-backup", name,
                               "Automated backups are disabled",
                               "Set a backup retention period so point-in-time recovery is possible."))
    return out
