"""IAM checks: MFA, stale access keys, admin policies, password policy."""

from __future__ import annotations

import datetime as dt

from . import finding

ADMIN_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
}
STALE_KEY_DAYS = 90


def _age_days(when) -> int:
    now = dt.datetime.now(tz=dt.timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return (now - when).days


def run(iam) -> list[dict]:
    out: list[dict] = []
    users = iam.list_users().get("Users", [])
    for u in users:
        name = u["UserName"]
        # MFA
        mfa = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
        if not mfa:
            out.append(finding("medium", "IAM", "mfa", name,
                               "IAM user has no MFA device",
                               "Enforce MFA for all human users, especially anyone with admin rights."))
        # Access keys
        for key in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
            if key.get("Status") != "Active":
                continue
            age = _age_days(key["CreateDate"])
            if age > STALE_KEY_DAYS:
                out.append(finding("medium", "IAM", "stale-key", f"{name}/{key['AccessKeyId'][:8]}…",
                                   f"Access key is {age} days old",
                                   "Rotate access keys at least every 90 days; prefer IAM roles."))
        # Admin policy
        attached = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
        groups = iam.list_groups_for_user(UserName=name).get("Groups", [])
        for g in groups:
            attached += iam.list_attached_group_policies(GroupName=g["GroupName"]).get("AttachedPolicies", [])
        if any(p["PolicyArn"] in ADMIN_ARNS for p in attached):
            out.append(finding("medium", "IAM", "admin-policy", name,
                               "User has AdministratorAccess",
                               "Confirm this is intentional; prefer scoped policies and break-glass admin roles."))
    # Password policy
    try:
        pol = iam.get_account_password_policy()["PasswordPolicy"]
    except Exception:
        pol = {}
    if not pol:
        out.append(finding("low", "IAM", "password-policy", "account",
                           "No IAM password policy set",
                           "Define minimum length (14+), complexity, and reuse prevention."))
    elif pol.get("MinimumPasswordLength", 0) < 14:
        out.append(finding("low", "IAM", "password-policy", "account",
                           f"Minimum password length is {pol.get('MinimumPasswordLength')}",
                           "CIS recommends 14+ characters."))
    return out
