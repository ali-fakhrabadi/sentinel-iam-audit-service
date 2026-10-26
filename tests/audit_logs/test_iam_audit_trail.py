"""Sentinel records its own privilege changes in the audit log."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from rest_framework.test import APIClient

from apps.accounts.models import ServiceAccount, User
from apps.accounts.services import IssuedAPIKey
from apps.audit_logs.models import AuditEvent, OutboxMessage
from tests.factories import DEFAULT_PASSWORD

pytestmark = pytest.mark.django_db
ClientFor = Callable[[User], APIClient]
MakeUser = Callable[..., User]


def test_role_assignment_is_audited_and_queued_for_alerting(
    admin_user: User, make_user: MakeUser, client_for: ClientFor
) -> None:
    target = make_user()

    client_for(admin_user).post(
        f"/api/v1/accounts/users/{target.pk}/roles/", {"role": "auditor"}, format="json"
    )

    event = AuditEvent.objects.get(action="iam.role.assigned")
    assert event.producer_user == admin_user
    assert event.actor_id == str(admin_user.pk)
    assert (event.resource_type, event.resource_id) == ("iam.user", str(target.pk))
    assert event.metadata == {"role": "auditor"}
    assert event.severity == "WARN"
    assert OutboxMessage.objects.filter(event=event).exists()


def test_rejected_changes_leave_no_audit_record(make_user: MakeUser, client_for: ClientFor) -> None:
    target = make_user()

    response = client_for(make_user(roles=["iam_manager"])).post(
        f"/api/v1/accounts/users/{target.pk}/roles/", {"role": "admin"}, format="json"
    )

    assert response.status_code == 403
    assert not AuditEvent.objects.filter(action="iam.role.assigned").exists()


def test_api_key_issuance_is_audited_without_the_secret(
    issue_key: Callable[..., tuple[ServiceAccount, IssuedAPIKey]], superuser: User
) -> None:
    account, issued = issue_key(scopes=["audit:write"])

    event = AuditEvent.objects.get(action="iam.api_key.issued")
    assert event.producer_user == superuser
    assert event.metadata["key_prefix"] == issued.api_key.prefix
    assert event.metadata["service_account"] == account.name
    assert issued.raw_key not in json.dumps(event.metadata)


def test_password_changes_are_audited(make_user: MakeUser, client_for: ClientFor) -> None:
    user = make_user()

    client_for(user).post(
        "/api/v1/accounts/me/password/",
        {"current_password": DEFAULT_PASSWORD, "new_password": "A-brand-new-passphrase-77"},
        format="json",
    )

    event = AuditEvent.objects.get(action="iam.password.changed")
    assert event.producer_user == user
    assert "A-brand-new-passphrase-77" not in json.dumps(event.metadata)


def test_user_deactivation_is_a_warning(
    admin_user: User, make_user: MakeUser, client_for: ClientFor
) -> None:
    target = make_user()

    client_for(admin_user).patch(
        f"/api/v1/accounts/users/{target.pk}/", {"is_active": False}, format="json"
    )

    event = AuditEvent.objects.get(action="iam.user.deactivated")
    assert event.severity == "WARN"
    assert event.metadata == {"is_active": False}
