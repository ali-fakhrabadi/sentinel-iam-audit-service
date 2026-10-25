"""HTTP layer for identities, RBAC and machine credentials.

Views stay thin: they validate input with serializers, call services or selectors,
and shape the response. Authorization lives in permission classes and services.
"""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.views import (
    TokenBlacklistView,
    TokenObtainPairView,
    TokenRefreshView,
)

from apps.accounts import selectors, services
from apps.accounts.authentication import APIKeyAuthentication
from apps.accounts.catalog import PermissionCode
from apps.accounts.filters import UserFilter
from apps.accounts.models import APIKey, User
from apps.accounts.pagination import ServiceAccountCursorPagination, UserCursorPagination
from apps.accounts.permissions import HasRequiredPermissions, IsHumanUser, IsServicePrincipal
from apps.accounts.serializers import (
    APIKeyCreateSerializer,
    APIKeyIntrospectionSerializer,
    APIKeyIssuedSerializer,
    APIKeySerializer,
    MeSerializer,
    PasswordChangeSerializer,
    PermissionSerializer,
    ProfileUpdateSerializer,
    RoleAssignmentSerializer,
    RoleCreateSerializer,
    RoleSerializer,
    RoleUpdateSerializer,
    ServiceAccountCreateSerializer,
    ServiceAccountSerializer,
    ServiceAccountUpdateSerializer,
    TokenPairSerializer,
    UserCreateSerializer,
    UserSerializer,
    UserUpdateSerializer,
)
from config.openapi import problem_response

AUTH_TAG = "Auth"
ACCOUNT_TAG = "Current user"
USERS_TAG = "Users"
ROLES_TAG = "Roles"
SERVICE_ACCOUNTS_TAG = "Service accounts"

_RequiredPermissions = dict[str, tuple[str, ...]]


def _actor(request: Request) -> User:
    user = request.user
    if not isinstance(user, User):  # guaranteed by IsHumanUser; narrows the type
        raise TypeError("Expected an authenticated user")
    return user


_HUMAN_PERMISSIONS = (IsAuthenticated, IsHumanUser, HasRequiredPermissions)


class HumanAPIView(APIView):
    """JWT users only, authorized by ``required_permissions`` per HTTP method."""

    permission_classes = _HUMAN_PERMISSIONS
    required_permissions: ClassVar[_RequiredPermissions] = {}


class HumanGenericAPIView(GenericAPIView):
    """Same policy as ``HumanAPIView``, with pagination and filtering support."""

    permission_classes = _HUMAN_PERMISSIONS
    required_permissions: ClassVar[_RequiredPermissions] = {}


# --------------------------------------------------------------------------------------
# Authentication (rate limited with the "auth" throttle scope)
# --------------------------------------------------------------------------------------
class TokenObtainView(TokenObtainPairView):
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "auth"

    @extend_schema(
        operation_id="auth_token_obtain",
        tags=[AUTH_TAG],
        summary="Log in: exchange email and password for a JWT pair",
        responses={
            200: TokenPairSerializer,
            401: problem_response("Unknown email, wrong password or inactive account"),
        },
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().post(request, *args, **kwargs)


class TokenRotateView(TokenRefreshView):
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "auth"

    @extend_schema(
        operation_id="auth_token_refresh",
        tags=[AUTH_TAG],
        summary="Rotate a refresh token",
        description="Returns a new access and refresh token. The submitted refresh token "
        "is blacklisted, so each refresh token works once.",
        request=TokenRefreshSerializer,
        responses={
            200: TokenPairSerializer,
            401: problem_response("Invalid, expired or already used refresh token"),
        },
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().post(request, *args, **kwargs)


class LogoutView(TokenBlacklistView):
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "auth"

    @extend_schema(
        operation_id="auth_logout",
        tags=[AUTH_TAG],
        summary="Log out: revoke a refresh token",
        responses={
            204: OpenApiResponse(description="Refresh token revoked"),
            401: problem_response("Invalid or already revoked refresh token"),
        },
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        super().post(request, *args, **kwargs)
        return Response(status=status.HTTP_204_NO_CONTENT)


class APIKeyIntrospectView(APIView):
    """Lets a machine client check which service account and scopes its key carries."""

    authentication_classes = (APIKeyAuthentication,)
    permission_classes = (IsServicePrincipal,)

    @extend_schema(
        operation_id="auth_api_key_introspect",
        tags=[AUTH_TAG],
        summary="Describe the calling API key",
        responses=APIKeyIntrospectionSerializer,
    )
    def get(self, request: Request) -> Response:
        api_key = request.auth
        if not isinstance(api_key, APIKey):  # guaranteed by IsServicePrincipal
            raise TypeError("Expected an API key")
        data = {
            "service_account_id": api_key.service_account.id,
            "service_account_name": api_key.service_account.name,
            "key_id": api_key.id,
            "key_name": api_key.name,
            "prefix": api_key.prefix,
            "scopes": api_key.scopes,
            "expires_at": api_key.expires_at,
        }
        return Response(APIKeyIntrospectionSerializer(data).data)


# --------------------------------------------------------------------------------------
# Current user
# --------------------------------------------------------------------------------------
class MeView(APIView):
    permission_classes = (IsAuthenticated, IsHumanUser)

    @extend_schema(
        operation_id="me_retrieve",
        tags=[ACCOUNT_TAG],
        summary="Current user, roles and flattened permissions",
        description="Bootstraps a SPA: profile, active role names and the sorted, "
        "de-duplicated permission codes for role-based UI rendering.",
        responses=MeSerializer,
    )
    def get(self, request: Request) -> Response:
        return Response(MeSerializer(MeSerializer.build(_actor(request))).data)

    @extend_schema(
        operation_id="me_update",
        tags=[ACCOUNT_TAG],
        summary="Update your own profile",
        request=ProfileUpdateSerializer,
        responses=MeSerializer,
    )
    def patch(self, request: Request) -> Response:
        serializer = ProfileUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = services.profile_update(
            user=_actor(request), full_name=serializer.validated_data["full_name"]
        )
        return Response(MeSerializer(MeSerializer.build(user)).data)


class PasswordChangeView(APIView):
    permission_classes = (IsAuthenticated, IsHumanUser)
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "auth"

    @extend_schema(
        operation_id="me_password_change",
        tags=[ACCOUNT_TAG],
        summary="Change your password and sign out everywhere",
        request=PasswordChangeSerializer,
        responses={204: OpenApiResponse(description="Password changed; all tokens revoked")},
    )
    def post(self, request: Request) -> Response:
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        services.password_change(user=_actor(request), **serializer.validated_data)
        return Response(status=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------------------
class UserListCreateView(HumanGenericAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {
        "GET": (PermissionCode.USERS_READ,),
        "POST": (PermissionCode.USERS_MANAGE,),
    }
    serializer_class = UserSerializer
    pagination_class = UserCursorPagination
    filterset_class = UserFilter

    def get_queryset(self) -> Any:
        return selectors.user_list()

    @extend_schema(
        operation_id="users_list",
        tags=[USERS_TAG],
        summary="List users",
        responses=UserSerializer(many=True),
    )
    def get(self, request: Request) -> Response:
        page = self.paginate_queryset(self.filter_queryset(self.get_queryset()))
        return self.get_paginated_response(UserSerializer(page, many=True).data)

    @extend_schema(
        operation_id="users_create",
        tags=[USERS_TAG],
        summary="Create a user",
        request=UserCreateSerializer,
        responses={201: UserSerializer, 409: problem_response("Email address already in use")},
    )
    def post(self, request: Request) -> Response:
        serializer = UserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = services.user_create(actor=_actor(request), **serializer.validated_data)
        return Response(
            UserSerializer(selectors.user_get(user.pk)).data, status=status.HTTP_201_CREATED
        )


class UserDetailView(HumanAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {
        "GET": (PermissionCode.USERS_READ,),
        "PATCH": (PermissionCode.USERS_MANAGE,),
    }

    @extend_schema(
        operation_id="users_retrieve",
        tags=[USERS_TAG],
        summary="Get a user",
        responses=UserSerializer,
    )
    def get(self, request: Request, user_id: uuid.UUID) -> Response:
        return Response(UserSerializer(selectors.user_get(user_id)).data)

    @extend_schema(
        operation_id="users_update",
        tags=[USERS_TAG],
        summary="Update or deactivate a user",
        description="Deactivation also revokes the user's refresh tokens.",
        request=UserUpdateSerializer,
        responses=UserSerializer,
    )
    def patch(self, request: Request, user_id: uuid.UUID) -> Response:
        serializer = UserUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        services.user_update(
            actor=_actor(request), user=selectors.user_get(user_id), **serializer.validated_data
        )
        return Response(UserSerializer(selectors.user_get(user_id)).data)


class UserRoleAssignView(HumanAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {"POST": (PermissionCode.ROLES_MANAGE,)}

    @extend_schema(
        operation_id="users_roles_assign",
        tags=[USERS_TAG],
        summary="Assign a role to a user",
        description="Idempotent: 201 when granted now, 200 when the user already held it. "
        "You cannot assign roles to yourself or grant permissions you do not hold.",
        request=RoleAssignmentSerializer,
        responses={201: UserSerializer, 200: UserSerializer},
    )
    def post(self, request: Request, user_id: uuid.UUID) -> Response:
        serializer = RoleAssignmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _, created = services.role_assign(
            actor=_actor(request),
            user=selectors.user_get(user_id),
            role=selectors.role_get(serializer.validated_data["role"]),
        )
        return Response(
            UserSerializer(selectors.user_get(user_id)).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class UserRoleRevokeView(HumanAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {
        "DELETE": (PermissionCode.ROLES_MANAGE,)
    }

    @extend_schema(
        operation_id="users_roles_revoke",
        tags=[USERS_TAG],
        summary="Revoke a role from a user",
        responses={204: OpenApiResponse(description="Role revoked")},
    )
    def delete(self, request: Request, user_id: uuid.UUID, role_name: str) -> Response:
        services.role_revoke(
            actor=_actor(request),
            user=selectors.user_get(user_id),
            role=selectors.role_get(role_name),
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------------------
# Roles and permissions
# --------------------------------------------------------------------------------------
class RoleListCreateView(HumanAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {
        "GET": (PermissionCode.ROLES_READ,),
        "POST": (PermissionCode.ROLES_MANAGE,),
    }

    @extend_schema(
        operation_id="roles_list",
        tags=[ROLES_TAG],
        summary="List roles with their permissions",
        responses=RoleSerializer(many=True),
    )
    def get(self, request: Request) -> Response:
        return Response(RoleSerializer(selectors.role_list(), many=True).data)

    @extend_schema(
        operation_id="roles_create",
        tags=[ROLES_TAG],
        summary="Create a custom role",
        request=RoleCreateSerializer,
        responses={201: RoleSerializer, 409: problem_response("Role name already in use")},
    )
    def post(self, request: Request) -> Response:
        serializer = RoleCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        role = services.role_create(
            actor=_actor(request),
            name=data["name"],
            description=data["description"],
            permission_codes=data["permissions"],
        )
        return Response(
            RoleSerializer(selectors.role_get(role.name)).data, status=status.HTTP_201_CREATED
        )


class RoleDetailView(HumanAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {
        "GET": (PermissionCode.ROLES_READ,),
        "PATCH": (PermissionCode.ROLES_MANAGE,),
        "DELETE": (PermissionCode.ROLES_MANAGE,),
    }

    @extend_schema(
        operation_id="roles_retrieve",
        tags=[ROLES_TAG],
        summary="Get a role",
        responses=RoleSerializer,
    )
    def get(self, request: Request, role_name: str) -> Response:
        return Response(RoleSerializer(selectors.role_get(role_name)).data)

    @extend_schema(
        operation_id="roles_update",
        tags=[ROLES_TAG],
        summary="Change a custom role",
        description="Built-in roles are immutable.",
        request=RoleUpdateSerializer,
        responses=RoleSerializer,
    )
    def patch(self, request: Request, role_name: str) -> Response:
        serializer = RoleUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        services.role_update(
            actor=_actor(request),
            role=selectors.role_get(role_name),
            description=data.get("description"),
            permission_codes=data.get("permissions"),
        )
        return Response(RoleSerializer(selectors.role_get(role_name)).data)

    @extend_schema(
        operation_id="roles_delete",
        tags=[ROLES_TAG],
        summary="Delete a custom role",
        responses={
            204: OpenApiResponse(description="Role deleted"),
            409: problem_response("Role still assigned to users"),
        },
    )
    def delete(self, request: Request, role_name: str) -> Response:
        services.role_delete(actor=_actor(request), role=selectors.role_get(role_name))
        return Response(status=status.HTTP_204_NO_CONTENT)


class PermissionListView(HumanAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {"GET": (PermissionCode.ROLES_READ,)}

    @extend_schema(
        operation_id="permissions_list",
        tags=[ROLES_TAG],
        summary="The permission catalog",
        responses=PermissionSerializer(many=True),
    )
    def get(self, request: Request) -> Response:
        return Response(PermissionSerializer(selectors.permission_list(), many=True).data)


# --------------------------------------------------------------------------------------
# Service accounts and API keys
# --------------------------------------------------------------------------------------
class ServiceAccountListCreateView(HumanGenericAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {
        "GET": (PermissionCode.SERVICE_ACCOUNTS_READ,),
        "POST": (PermissionCode.SERVICE_ACCOUNTS_MANAGE,),
    }
    serializer_class = ServiceAccountSerializer
    pagination_class = ServiceAccountCursorPagination

    def get_queryset(self) -> Any:
        return selectors.service_account_list()

    @extend_schema(
        operation_id="service_accounts_list",
        tags=[SERVICE_ACCOUNTS_TAG],
        summary="List service accounts",
        responses=ServiceAccountSerializer(many=True),
    )
    def get(self, request: Request) -> Response:
        page = self.paginate_queryset(self.get_queryset())
        return self.get_paginated_response(ServiceAccountSerializer(page, many=True).data)

    @extend_schema(
        operation_id="service_accounts_create",
        tags=[SERVICE_ACCOUNTS_TAG],
        summary="Create a service account",
        request=ServiceAccountCreateSerializer,
        responses={201: ServiceAccountSerializer, 409: problem_response("Name already in use")},
    )
    def post(self, request: Request) -> Response:
        serializer = ServiceAccountCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        service_account = services.service_account_create(
            actor=_actor(request), **serializer.validated_data
        )
        return Response(
            ServiceAccountSerializer(selectors.service_account_get(service_account.pk)).data,
            status=status.HTTP_201_CREATED,
        )


class ServiceAccountDetailView(HumanAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {
        "GET": (PermissionCode.SERVICE_ACCOUNTS_READ,),
        "PATCH": (PermissionCode.SERVICE_ACCOUNTS_MANAGE,),
    }

    @extend_schema(
        operation_id="service_accounts_retrieve",
        tags=[SERVICE_ACCOUNTS_TAG],
        summary="Get a service account",
        responses=ServiceAccountSerializer,
    )
    def get(self, request: Request, service_account_id: uuid.UUID) -> Response:
        return Response(
            ServiceAccountSerializer(selectors.service_account_get(service_account_id)).data
        )

    @extend_schema(
        operation_id="service_accounts_update",
        tags=[SERVICE_ACCOUNTS_TAG],
        summary="Update or disable a service account",
        description="Disabling a service account immediately invalidates all of its keys.",
        request=ServiceAccountUpdateSerializer,
        responses=ServiceAccountSerializer,
    )
    def patch(self, request: Request, service_account_id: uuid.UUID) -> Response:
        serializer = ServiceAccountUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        services.service_account_update(
            actor=_actor(request),
            service_account=selectors.service_account_get(service_account_id),
            **serializer.validated_data,
        )
        return Response(
            ServiceAccountSerializer(selectors.service_account_get(service_account_id)).data
        )


class APIKeyListCreateView(HumanAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {
        "GET": (PermissionCode.SERVICE_ACCOUNTS_READ,),
        "POST": (PermissionCode.API_KEYS_MANAGE,),
    }

    @extend_schema(
        operation_id="api_keys_list",
        tags=[SERVICE_ACCOUNTS_TAG],
        summary="List a service account's API keys (metadata only)",
        responses=APIKeySerializer(many=True),
    )
    def get(self, request: Request, service_account_id: uuid.UUID) -> Response:
        service_account = selectors.service_account_get(service_account_id)
        return Response(APIKeySerializer(selectors.api_key_list(service_account), many=True).data)

    @extend_schema(
        operation_id="api_keys_create",
        tags=[SERVICE_ACCOUNTS_TAG],
        summary="Issue an API key",
        description="The response contains the raw key exactly once; only its SHA-256 digest "
        "is stored. Scopes must be permissions you hold yourself.",
        request=APIKeyCreateSerializer,
        responses={201: APIKeyIssuedSerializer},
    )
    def post(self, request: Request, service_account_id: uuid.UUID) -> Response:
        serializer = APIKeyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        issued = services.api_key_issue(
            actor=_actor(request),
            service_account=selectors.service_account_get(service_account_id),
            **serializer.validated_data,
        )
        payload = {**APIKeySerializer(issued.api_key).data, "key": issued.raw_key}
        response = Response(payload, status=status.HTTP_201_CREATED)
        # The raw key must not be kept by browsers or intermediary caches.
        response["Cache-Control"] = "no-store"
        return response


class APIKeyRevokeView(HumanAPIView):
    required_permissions: ClassVar[_RequiredPermissions] = {
        "POST": (PermissionCode.API_KEYS_MANAGE,)
    }

    @extend_schema(
        operation_id="api_keys_revoke",
        tags=[SERVICE_ACCOUNTS_TAG],
        summary="Revoke an API key",
        description="Takes effect immediately. Idempotent.",
        request=None,
        responses=APIKeySerializer,
    )
    def post(self, request: Request, service_account_id: uuid.UUID, key_id: uuid.UUID) -> Response:
        service_account = selectors.service_account_get(service_account_id)
        api_key = services.api_key_revoke(
            actor=_actor(request), api_key=selectors.api_key_get(service_account, key_id)
        )
        return Response(APIKeySerializer(api_key).data)
