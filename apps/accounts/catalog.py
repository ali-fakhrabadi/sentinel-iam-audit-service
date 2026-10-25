"""The permission catalog and built-in roles.

Permission codes follow ``<resource>:<action>``. They are the single vocabulary for
both human users (granted through roles) and service accounts (granted as API key
scopes). Migration ``0002_seed_rbac_catalog`` writes this catalog to the database
and a test keeps the two in sync.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class PermissionCode(StrEnum):
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    ROLES_READ = "roles:read"
    ROLES_MANAGE = "roles:manage"
    SERVICE_ACCOUNTS_READ = "service_accounts:read"
    SERVICE_ACCOUNTS_MANAGE = "service_accounts:manage"
    API_KEYS_MANAGE = "api_keys:manage"
    AUDIT_READ = "audit:read"
    AUDIT_WRITE = "audit:write"
    WEBHOOKS_READ = "webhooks:read"
    WEBHOOKS_MANAGE = "webhooks:manage"


PERMISSION_DESCRIPTIONS: Final[dict[PermissionCode, str]] = {
    PermissionCode.USERS_READ: "View user accounts and their role assignments.",
    PermissionCode.USERS_MANAGE: "Create, update and deactivate user accounts.",
    PermissionCode.ROLES_READ: "View roles and the permission catalog.",
    PermissionCode.ROLES_MANAGE: "Create, change and delete custom roles; assign and revoke roles.",
    PermissionCode.SERVICE_ACCOUNTS_READ: "View service accounts and their API key metadata.",
    PermissionCode.SERVICE_ACCOUNTS_MANAGE: "Create and update service accounts.",
    PermissionCode.API_KEYS_MANAGE: "Issue and revoke API keys for service accounts.",
    PermissionCode.AUDIT_READ: "Query security audit events.",
    PermissionCode.AUDIT_WRITE: "Ingest security audit events.",
    PermissionCode.WEBHOOKS_READ: "View webhook endpoints and delivery status.",
    PermissionCode.WEBHOOKS_MANAGE: "Create and update webhook endpoints and rotate their secrets.",
}

SYSTEM_ROLES: Final[dict[str, tuple[str, frozenset[PermissionCode]]]] = {
    "admin": ("Full access to every Sentinel API.", frozenset(PermissionCode)),
    "iam_manager": (
        "Manages users and roles, limited to permissions the manager holds.",
        frozenset(
            {
                PermissionCode.USERS_READ,
                PermissionCode.USERS_MANAGE,
                PermissionCode.ROLES_READ,
                PermissionCode.ROLES_MANAGE,
            }
        ),
    ),
    "security_analyst": (
        "Investigates security events; read-only access to IAM and webhooks.",
        frozenset(
            {
                PermissionCode.AUDIT_READ,
                PermissionCode.WEBHOOKS_READ,
                PermissionCode.USERS_READ,
                PermissionCode.ROLES_READ,
                PermissionCode.SERVICE_ACCOUNTS_READ,
            }
        ),
    ),
    "auditor": ("Read-only access to audit events.", frozenset({PermissionCode.AUDIT_READ})),
}
