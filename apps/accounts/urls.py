from __future__ import annotations

from django.urls import path

from apps.accounts import views

urlpatterns = [
    path("auth/token/", views.TokenObtainView.as_view(), name="auth-token-obtain"),
    path("auth/token/refresh/", views.TokenRotateView.as_view(), name="auth-token-refresh"),
    path("auth/logout/", views.LogoutView.as_view(), name="auth-logout"),
    path(
        "auth/api-key/introspect/",
        views.APIKeyIntrospectView.as_view(),
        name="auth-api-key-introspect",
    ),
    path("accounts/me/", views.MeView.as_view(), name="me"),
    path("accounts/me/password/", views.PasswordChangeView.as_view(), name="me-password"),
    path("accounts/users/", views.UserListCreateView.as_view(), name="user-list"),
    path("accounts/users/<uuid:user_id>/", views.UserDetailView.as_view(), name="user-detail"),
    path(
        "accounts/users/<uuid:user_id>/roles/",
        views.UserRoleAssignView.as_view(),
        name="user-roles",
    ),
    path(
        "accounts/users/<uuid:user_id>/roles/<slug:role_name>/",
        views.UserRoleRevokeView.as_view(),
        name="user-role-detail",
    ),
    path("accounts/roles/", views.RoleListCreateView.as_view(), name="role-list"),
    path("accounts/roles/<slug:role_name>/", views.RoleDetailView.as_view(), name="role-detail"),
    path("accounts/permissions/", views.PermissionListView.as_view(), name="permission-list"),
    path(
        "accounts/service-accounts/",
        views.ServiceAccountListCreateView.as_view(),
        name="service-account-list",
    ),
    path(
        "accounts/service-accounts/<uuid:service_account_id>/",
        views.ServiceAccountDetailView.as_view(),
        name="service-account-detail",
    ),
    path(
        "accounts/service-accounts/<uuid:service_account_id>/api-keys/",
        views.APIKeyListCreateView.as_view(),
        name="api-key-list",
    ),
    path(
        "accounts/service-accounts/<uuid:service_account_id>/api-keys/<uuid:key_id>/revoke/",
        views.APIKeyRevokeView.as_view(),
        name="api-key-revoke",
    ),
]
