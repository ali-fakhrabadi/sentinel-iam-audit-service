from __future__ import annotations

import django_filters

from apps.accounts.models import User


class UserFilter(django_filters.FilterSet):
    email = django_filters.CharFilter(
        field_name="email", lookup_expr="icontains", help_text="Case-insensitive substring"
    )
    is_active = django_filters.BooleanFilter()
    role = django_filters.CharFilter(
        field_name="roles__name", distinct=True, help_text="Users holding this role"
    )

    class Meta:
        model = User
        fields = ("email", "is_active", "role")
