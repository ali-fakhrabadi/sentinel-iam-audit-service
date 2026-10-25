"""Cursor pagination for account collections.

Cursor pagination keeps pages stable while rows are inserted and never runs
``COUNT(*)`` or large ``OFFSET`` scans.
"""

from __future__ import annotations

from rest_framework.pagination import CursorPagination


class _AccountsCursorPagination(CursorPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200


class UserCursorPagination(_AccountsCursorPagination):
    ordering = ("-date_joined", "-id")


class ServiceAccountCursorPagination(_AccountsCursorPagination):
    ordering = ("name",)
