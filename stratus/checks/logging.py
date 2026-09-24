"""Logging checks: CloudTrail coverage."""

from __future__ import annotations

from . import finding


def run(ct) -> list[dict]:
    out: list[dict] = []
    trails = ct.describe_trails().get("trailList", [])
    if not trails:
        return [finding("high", "CloudTrail", "no-trail", "account",
                        "No CloudTrail trails configured",
                        "Without CloudTrail there is no API audit log — incidents become uninvestigable. "
                        "Create a multi-region trail with log file validation.")]
    for t in trails:
        name = t.get("Name", "?")
        if not t.get("IsMultiRegionTrail"):
            out.append(finding("medium", "CloudTrail", "single-region", name,
                               "Trail is not multi-region",
                               "A single-region trail misses activity elsewhere; enable multi-region."))
        if not t.get("LogFileValidationEnabled"):
            out.append(finding("low", "CloudTrail", "no-validation", name,
                               "Log file validation is disabled",
                               "Validation detects tampering of log files after delivery."))
        status = ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging", False)
        if not status:
            out.append(finding("high", "CloudTrail", "not-logging", name,
                               "Trail exists but is not logging",
                               "A disabled trail provides zero visibility; re-enable it."))
    return out
