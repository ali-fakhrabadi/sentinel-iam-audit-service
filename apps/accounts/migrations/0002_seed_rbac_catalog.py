"""Seed the permission catalog and the built-in roles.

The data is a frozen copy of ``apps/accounts/catalog.py`` at the time of writing, as
migrations must not depend on code that changes later. ``tests/accounts/test_catalog.py``
fails if the two drift apart; extend the catalog with a new data migration.
"""

from django.db import migrations

PERMISSIONS = {
    "users:read": "View user accounts and their role assignments.",
    "users:manage": "Create, update and deactivate user accounts.",
    "roles:read": "View roles and the permission catalog.",
    "roles:manage": "Create, change and delete custom roles; assign and revoke roles.",
    "service_accounts:read": "View service accounts and their API key metadata.",
    "service_accounts:manage": "Create and update service accounts.",
    "api_keys:manage": "Issue and revoke API keys for service accounts.",
    "audit:read": "Query security audit events.",
    "audit:write": "Ingest security audit events.",
    "webhooks:read": "View webhook endpoints and delivery status.",
    "webhooks:manage": "Create and update webhook endpoints and rotate their secrets.",
}

SYSTEM_ROLES = {
    "admin": ("Full access to every Sentinel API.", sorted(PERMISSIONS)),
    "iam_manager": (
        "Manages users and roles, limited to permissions the manager holds.",
        ["users:read", "users:manage", "roles:read", "roles:manage"],
    ),
    "security_analyst": (
        "Investigates security events; read-only access to IAM and webhooks.",
        ["audit:read", "webhooks:read", "users:read", "roles:read", "service_accounts:read"],
    ),
    "auditor": ("Read-only access to audit events.", ["audit:read"]),
}


def seed_catalog(apps, schema_editor):
    Permission = apps.get_model("accounts", "Permission")
    Role = apps.get_model("accounts", "Role")
    for code, description in PERMISSIONS.items():
        Permission.objects.update_or_create(code=code, defaults={"description": description})
    for name, (description, codes) in SYSTEM_ROLES.items():
        role, _ = Role.objects.update_or_create(
            name=name, defaults={"description": description, "is_system": True}
        )
        role.permissions.set(Permission.objects.filter(code__in=codes))


def remove_catalog(apps, schema_editor):
    UserRole = apps.get_model("accounts", "UserRole")
    Role = apps.get_model("accounts", "Role")
    Permission = apps.get_model("accounts", "Permission")
    UserRole.objects.filter(role__name__in=SYSTEM_ROLES).delete()
    Role.objects.filter(name__in=SYSTEM_ROLES, is_system=True).delete()
    Permission.objects.filter(code__in=PERMISSIONS).delete()


class Migration(migrations.Migration):
    dependencies = [("accounts", "0001_initial")]

    operations = [migrations.RunPython(seed_catalog, remove_catalog)]
