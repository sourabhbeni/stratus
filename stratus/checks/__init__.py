"""Shared helpers for checks."""

from __future__ import annotations


def finding(severity: str, service: str, check: str, resource: str, title: str, detail: str = "") -> dict:
    return {
        "severity": severity, "service": service, "check": check,
        "resource": resource, "title": title, "detail": detail,
    }


def is_open_to_world(permission: dict) -> bool:
    """True if an EC2 security-group IpPermission allows 0.0.0.0/0 or ::/0."""
    for rng in permission.get("IpRanges", []):
        if rng.get("CidrIp") == "0.0.0.0/0":
            return True
    for rng in permission.get("Ipv6Ranges", []):
        if rng.get("CidrIpv6") == "::/0":
            return True
    return False


def ports_covered(permission: dict) -> set[int] | None:
    """Ports a permission covers, or None for all ports (-1 / all protocols)."""
    if permission.get("IpProtocol") == "-1":
        return None
    fp, tp = permission.get("FromPort"), permission.get("ToPort")
    if fp is None or tp is None:
        return None
    return set(range(fp, tp + 1))
