"""Give every searchable filter an index that ends in the (created_at, id) sort key.

* actor, resource, action and severity indexes gain ``id``;
* new indexes for ``ip_address`` and for the producing service account (the scope of
  every API-key read); the latter replaces the plain foreign-key index.

All indexes are built and dropped CONCURRENTLY, new ones before old ones, so a large audit
table stays writable and never runs without a filter index. Concurrent operations cannot
run inside a transaction, hence ``atomic = False``. If a build is interrupted it leaves
an INVALID index behind; drop it and run ``migrate`` again.
"""

from django.contrib.postgres.operations import AddIndexConcurrently, RemoveIndexConcurrently
from django.db import migrations, models
from django.db.models import Q

# Name Django generated for the foreign-key index in 0001 (derived from table and column).
FK_INDEX = "audit_logs_auditevent_producer_service_account_id_b29284cc"


def add(name: str, fields: list[str], condition: Q | None = None) -> AddIndexConcurrently:
    return AddIndexConcurrently(
        model_name="auditevent",
        index=models.Index(fields=fields, name=name, condition=condition),
    )


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("accounts", "0002_seed_rbac_catalog"),
        ("audit_logs", "0002_append_only_guards"),
    ]

    operations = [
        add(
            "audit_actor_created_id_idx",
            ["actor_id", "created_at", "id"],
            Q(actor_id__isnull=False),
        ),
        add(
            "audit_resource_created_id_idx",
            ["resource_type", "resource_id", "created_at", "id"],
        ),
        add("audit_action_created_id_idx", ["action", "created_at", "id"]),
        add(
            "audit_ip_created_id_idx",
            ["ip_address", "created_at", "id"],
            Q(ip_address__isnull=False),
        ),
        add(
            "audit_producer_created_id_idx",
            ["producer_service_account", "created_at", "id"],
            Q(producer_service_account__isnull=False),
        ),
        add(
            "audit_severity_created_id_idx",
            ["severity", "created_at", "id"],
            Q(("severity", "INFO"), _negated=True),
        ),
        RemoveIndexConcurrently(model_name="auditevent", name="audit_actor_created_idx"),
        RemoveIndexConcurrently(model_name="auditevent", name="audit_resource_created_idx"),
        RemoveIndexConcurrently(model_name="auditevent", name="audit_action_created_idx"),
        RemoveIndexConcurrently(model_name="auditevent", name="audit_severity_created_idx"),
        # The composite producer index above serves foreign-key (PROTECT) lookups too.
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="auditevent",
                    name="producer_service_account",
                    field=models.ForeignKey(
                        blank=True,
                        db_index=False,
                        null=True,
                        on_delete=models.PROTECT,
                        related_name="+",
                        to="accounts.serviceaccount",
                    ),
                ),
            ],
            database_operations=[
                migrations.RunSQL(
                    f'DROP INDEX CONCURRENTLY IF EXISTS "{FK_INDEX}"',
                    reverse_sql=(
                        f'CREATE INDEX CONCURRENTLY IF NOT EXISTS "{FK_INDEX}" '
                        'ON "audit_logs_auditevent" ("producer_service_account_id")'
                    ),
                ),
            ],
        ),
    ]
