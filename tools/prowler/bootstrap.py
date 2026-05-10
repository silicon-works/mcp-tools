#!/usr/bin/env python3
"""
Bootstrap a Prowler App tenant + admin user + TenantAPIKey for unattended
(MCP-driven) operation. Prints the plain-text API key (one line, last) to
stdout. Container's entrypoint captures that line and exports it as
PROWLER_APP_API_KEY for the MCP server.

Run AFTER `python manage.py migrate --database=admin` has succeeded.
Must run as the `default` (prowler_user) connection — NOT admin — because
RLS policies only fire for the regular user; running as admin bypasses RLS
and creates rows the API server cannot subsequently see.

Returns one line on stdout: the raw API key (form: `pk_<8>.<encrypted>`).
All diagnostics go to stderr.
"""
import os
import sys

# entrypoint exports PROWLER_API_DIR=/opt/prowler-src/api/src/backend.
# manage.py adds cwd to sys.path implicitly; we don't get that.
_api_dir = os.environ.get("PROWLER_API_DIR", "/opt/prowler-src/api/src/backend")
if _api_dir not in sys.path:
    sys.path.insert(0, _api_dir)

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.production")
django.setup()

from django.db import IntegrityError, transaction  # noqa: E402

from api.db_utils import rls_transaction  # noqa: E402
from api.models import (  # noqa: E402
    Membership,
    Role,
    TenantAPIKey,
    User,
    UserRoleRelationship,
)
from api.rls import Tenant  # noqa: E402

TENANT_NAME = os.environ.get("PROWLER_BOOTSTRAP_TENANT", "opensploit-engagement")
USER_EMAIL = os.environ.get("PROWLER_BOOTSTRAP_EMAIL", "agent@opensploit.local")
USER_NAME = os.environ.get("PROWLER_BOOTSTRAP_USER_NAME", "OpenSploit Agent")
KEY_NAME = os.environ.get("PROWLER_BOOTSTRAP_KEY_NAME", "opensploit-mcp")
ROLE_NAME = "admin"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def get_or_create_tenant() -> Tenant:
    """Tenant table is NOT RLS-protected; idempotent by name."""
    tenant, created = Tenant.objects.get_or_create(name=TENANT_NAME)
    log(f"tenant {'created' if created else 'reused'}: id={tenant.id} name={tenant.name}")
    return tenant


def get_or_create_user() -> User:
    """User.email is unique (case-insensitive normalized in User.save())."""
    email = USER_EMAIL.strip().lower()
    user = User.objects.filter(email=email).first()
    if user:
        log(f"user reused: id={user.id} email={user.email}")
        return user
    user = User(name=USER_NAME, email=USER_EMAIL, is_active=True)
    user.set_unusable_password()  # API-key-only account; no password login
    user.save()
    log(f"user created: id={user.id} email={user.email}")
    return user


def ensure_membership(user: User, tenant: Tenant) -> None:
    """Membership has BaseSecurityConstraint (not RLS); plain ORM works."""
    obj, created = Membership.objects.get_or_create(
        user=user,
        tenant=tenant,
        defaults={"role": Membership.RoleChoices.OWNER},
    )
    log(f"membership {'created' if created else 'reused'}: role={obj.role}")


def ensure_admin_role(tenant: Tenant, user: User) -> None:
    """
    Role + UserRoleRelationship + TenantAPIKey are RowLevelSecurityProtectedModel.
    Writes require api.tenant_id GUC to be set in-session via rls_transaction.
    Without the wrapper, INSERTs return 0 rows (RLS empty result set, no error).
    """
    with rls_transaction(str(tenant.id)):
        role, created = Role.objects.get_or_create(
            name=ROLE_NAME,
            tenant_id=tenant.id,
            defaults=dict(
                manage_users=True,
                manage_account=True,
                manage_billing=True,
                manage_providers=True,
                manage_integrations=True,
                manage_scans=True,
                unlimited_visibility=True,
            ),
        )
        log(f"role {'created' if created else 'reused'}: id={role.id} name={role.name}")
        rel, created = UserRoleRelationship.objects.get_or_create(
            user=user,
            role=role,
            tenant_id=tenant.id,
        )
        log(f"role-binding {'created' if created else 'reused'}: id={rel.id}")


def issue_api_key(tenant: Tenant, user: User) -> str:
    """
    TenantAPIKey has UniqueConstraint(tenant_id, name) AND the plaintext is
    unrecoverable after creation (encrypted via drf_simple_apikey Fernet).
    On IntegrityError (existing key with same name from a prior bootstrap that
    wasn't cached), append a random suffix and retry.
    """
    with rls_transaction(str(tenant.id)):
        name = KEY_NAME
        for attempt in range(5):
            try:
                _, raw = TenantAPIKey.objects.create_api_key(
                    name=name,
                    tenant_id=tenant.id,
                    entity=user,
                )
                log(f"api key minted: name={name}")
                return raw
            except IntegrityError:
                name = f"{KEY_NAME}-{os.urandom(3).hex()}"
                log(f"api key name collision, retrying with name={name}")
        raise RuntimeError("Could not allocate a unique TenantAPIKey name after 5 attempts")


def main() -> int:
    with transaction.atomic():
        tenant = get_or_create_tenant()
        user = get_or_create_user()
        ensure_membership(user, tenant)
    ensure_admin_role(tenant, user)        # own RLS txn
    raw_key = issue_api_key(tenant, user)  # own RLS txn

    if not raw_key.startswith("pk_"):
        log(f"ERROR: api key missing pk_ prefix (got: {raw_key[:8]}...)")
        return 1

    print(raw_key)  # ONE LINE on stdout — entrypoint captures via tail -n1
    return 0


if __name__ == "__main__":
    sys.exit(main())
