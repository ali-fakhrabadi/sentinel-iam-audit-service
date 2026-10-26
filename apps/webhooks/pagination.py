from __future__ import annotations

from rest_framework.pagination import CursorPagination


class DeliveryCursorPagination(CursorPagination):
    ordering = ("-created_at", "-id")
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200
