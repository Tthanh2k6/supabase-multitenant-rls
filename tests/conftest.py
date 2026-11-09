"""Builds a throwaway database once per test session: Supabase stub, migration, seed data.

Set DATABASE_URL to a PostgreSQL 15+ server where the connecting user can create databases
(CI uses the postgres superuser of a service container).
"""
import json
import os
import uuid
from pathlib import Path

import psycopg
import pytest

ROOT = Path(__file__).resolve().parent.parent
STUB = ROOT / "tests" / "supabase_stub.sql"
MIGRATIONS = sorted((ROOT / "supabase" / "migrations").glob("*.sql"))

USERS = {
    "alice": uuid.UUID("00000000-0000-0000-0000-00000000a001"),  # owner of tenant A
    "adam": uuid.UUID("00000000-0000-0000-0000-00000000a002"),   # member of tenant A
    "bob": uuid.UUID("00000000-0000-0000-0000-00000000b001"),    # owner of tenant B
    "eve": uuid.UUID("00000000-0000-0000-0000-00000000e001"),    # member of A and B
    "nora": uuid.UUID("00000000-0000-0000-0000-00000000f001"),   # signed in, no tenant
}


def _admin_url():
    return os.environ.get("DATABASE_URL", "postgresql://postgres@127.0.0.1:5432/postgres")


@pytest.fixture(scope="session")
def db_url():
    name = "mt_rls_" + uuid.uuid4().hex[:8]
    base = _admin_url()
    with psycopg.connect(base, autocommit=True) as admin:
        admin.execute(f'create database "{name}"')
    url = base.rsplit("/", 1)[0] + "/" + name
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(STUB.read_text(encoding="utf-8"))
        for migration in MIGRATIONS:
            conn.execute(migration.read_text(encoding="utf-8"))
        _seed(conn)
    yield url
    with psycopg.connect(base, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{name}" with (force)')


def _claims(user_id, extra=None):
    claims = {"sub": str(user_id), "role": "authenticated"}
    claims.update(extra or {})
    return json.dumps(claims)


def _as(conn, user_id):
    conn.execute("set role authenticated")
    conn.execute("select set_config('request.jwt.claims', %s, false)", (_claims(user_id),))


def _reset(conn):
    conn.execute("reset role")
    conn.execute("select set_config('request.jwt.claims', '', false)")


def _seed(conn):
    for name, uid in USERS.items():
        conn.execute("insert into auth.users (id, email) values (%s, %s)", (uid, f"{name}@example.test"))
    _as(conn, USERS["alice"])
    tenant_a = conn.execute("select public.create_tenant('Tenant A', 'tenant-a')").fetchone()[0]
    _as(conn, USERS["bob"])
    tenant_b = conn.execute("select public.create_tenant('Tenant B', 'tenant-b')").fetchone()[0]
    _reset(conn)
    conn.execute(
        "insert into public.memberships (tenant_id, user_id, role) values (%s, %s, 'member'), (%s, %s, 'member'), (%s, %s, 'member')",
        (tenant_a, USERS["adam"], tenant_a, USERS["eve"], tenant_b, USERS["eve"]),
    )
    conn.execute(
        "insert into public.projects (id, tenant_id, name) values "
        "('10000000-0000-0000-0000-00000000000a', %s, 'A roadmap'), "
        "('10000000-0000-0000-0000-00000000000b', %s, 'B roadmap')",
        (tenant_a, tenant_b),
    )
    conn.execute(
        "insert into public.documents (tenant_id, project_id, title) values "
        "(%s, '10000000-0000-0000-0000-00000000000a', 'A plan'), "
        "(%s, '10000000-0000-0000-0000-00000000000b', 'B plan')",
        (tenant_a, tenant_b),
    )
    conn.execute(
        "insert into storage.objects (bucket_id, name) values "
        "('tenant-files', %s), ('tenant-files', %s)",
        (f"{tenant_a}/contract.pdf", f"{tenant_b}/contract.pdf"),
    )
    conn.execute("create table public._seed (key text primary key, value uuid)")
    conn.execute("insert into public._seed values ('tenant_a', %s), ('tenant_b', %s)", (tenant_a, tenant_b))


@pytest.fixture
def conn(db_url):
    """One transaction per test, always rolled back."""
    with psycopg.connect(db_url) as connection:
        yield connection
        connection.rollback()


@pytest.fixture
def tenants(conn):
    rows = dict(conn.execute("select key, value from public._seed").fetchall())
    return rows["tenant_a"], rows["tenant_b"]


@pytest.fixture
def act(conn):
    """act(user, sql, params, extra_claims=None) runs SQL as that signed-in user inside the test transaction."""

    def run(user, sql, params=(), extra_claims=None):
        conn.execute("set local role authenticated")
        conn.execute("select set_config('request.jwt.claims', %s, true)", (_claims(USERS[user], extra_claims),))
        cur = conn.execute(sql, params)
        return cur.fetchall() if cur.description else cur.rowcount

    return run
