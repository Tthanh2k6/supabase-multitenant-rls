"""Tenant isolation tests: every check signs in as a real user and tries to cross a tenant boundary."""
import psycopg
import pytest
from psycopg import errors

A_PROJECT = "10000000-0000-0000-0000-00000000000a"
B_PROJECT = "10000000-0000-0000-0000-00000000000b"


def expect_error(conn, error, fn):
    with pytest.raises(error):
        with conn.transaction():
            fn()


# --- reading -----------------------------------------------------------------

def test_each_user_sees_only_their_tenant(act):
    assert act("alice", "select name from public.projects order by name") == [("A roadmap",)]
    assert act("bob", "select name from public.projects order by name") == [("B roadmap",)]
    assert act("alice", "select title from public.documents") == [("A plan",)]
    assert act("bob", "select slug from public.tenants") == [("tenant-b",)]


def test_member_of_two_tenants_sees_both(act):
    rows = act("eve", "select name from public.projects order by name")
    assert rows == [("A roadmap",), ("B roadmap",)]


def test_user_without_tenant_sees_nothing(act):
    for table in ("tenants", "memberships", "projects", "documents"):
        assert act("nora", f"select count(*) from public.{table}") == [(0,)]


def test_reading_another_tenant_by_id_returns_nothing(act):
    assert act("alice", "select * from public.projects where id = %s", (B_PROJECT,)) == []


# --- writing -----------------------------------------------------------------

def test_cannot_insert_into_another_tenant(conn, act, tenants):
    _, tenant_b = tenants
    expect_error(conn, errors.InsufficientPrivilege, lambda: act(
        "alice", "insert into public.projects (tenant_id, name) values (%s, 'sneaky')", (tenant_b,)))


def test_cannot_move_a_row_to_another_tenant(conn, act, tenants):
    _, tenant_b = tenants
    expect_error(conn, errors.InsufficientPrivilege, lambda: act(
        "alice", "update public.projects set tenant_id = %s where id = %s", (tenant_b, A_PROJECT)))


def test_updating_another_tenants_row_changes_nothing(act):
    assert act("alice", "update public.projects set name = 'pwned' where id = %s", (B_PROJECT,)) == 0
    assert act("bob", "select name from public.projects where id = %s", (B_PROJECT,)) == [("B roadmap",)]


def test_cannot_point_a_document_at_another_tenants_project(conn, act, tenants):
    tenant_a, _ = tenants
    # tenant_id passes the policy, but the composite foreign key rejects the cross-tenant parent.
    expect_error(conn, errors.ForeignKeyViolation, lambda: act(
        "alice", "insert into public.documents (tenant_id, project_id, title) values (%s, %s, 'x')",
        (tenant_a, B_PROJECT)))


def test_deleting_another_tenants_rows_changes_nothing(act):
    assert act("alice", "delete from public.documents where project_id = %s", (B_PROJECT,)) == 0
    assert act("bob", "select count(*) from public.documents") == [(1,)]


# --- roles inside a tenant ---------------------------------------------------

def test_member_cannot_add_members(conn, act, tenants):
    tenant_a, _ = tenants
    expect_error(conn, errors.InsufficientPrivilege, lambda: act(
        "adam", "insert into public.memberships (tenant_id, user_id, role) values (%s, %s, 'member')",
        (tenant_a, "00000000-0000-0000-0000-00000000f001")))


def test_owner_can_add_members_only_to_their_tenant(conn, act, tenants):
    tenant_a, tenant_b = tenants
    nora = "00000000-0000-0000-0000-00000000f001"
    assert act("alice", "insert into public.memberships (tenant_id, user_id, role) values (%s, %s, 'member')",
               (tenant_a, nora)) == 1
    expect_error(conn, errors.InsufficientPrivilege, lambda: act(
        "alice", "insert into public.memberships (tenant_id, user_id, role) values (%s, %s, 'admin')",
        (tenant_b, nora)))


def test_nobody_can_hand_out_owner(conn, act, tenants):
    tenant_a, _ = tenants
    expect_error(conn, errors.InsufficientPrivilege, lambda: act(
        "alice", "insert into public.memberships (tenant_id, user_id, role) values (%s, %s, 'owner')",
        (tenant_a, "00000000-0000-0000-0000-00000000f001")))


def test_role_in_user_metadata_is_ignored(conn, act, tenants):
    tenant_a, _ = tenants
    # Users can edit user_metadata themselves; claiming "admin" there must not grant anything.
    fake_admin = {"user_metadata": {"role": "admin"}}
    expect_error(conn, errors.InsufficientPrivilege, lambda: act(
        "adam", "insert into public.memberships (tenant_id, user_id, role) values (%s, %s, 'member')",
        (tenant_a, "00000000-0000-0000-0000-00000000f001"), extra_claims=fake_admin))


def test_member_cannot_delete_projects_but_owner_can(act):
    assert act("adam", "delete from public.projects where id = %s", (A_PROJECT,)) == 0
    assert act("alice", "delete from public.projects where id = %s", (A_PROJECT,)) == 1


def test_member_sees_only_own_membership_row(act):
    assert act("adam", "select count(*) from public.memberships") == [(1,)]
    assert act("alice", "select count(*) from public.memberships") == [(3,)]


# --- storage -----------------------------------------------------------------

def test_storage_files_are_scoped_to_the_tenant_folder(conn, act, tenants):
    tenant_a, tenant_b = tenants
    names = act("alice", "select name from storage.objects order by name")
    assert names == [(f"{tenant_a}/contract.pdf",)]
    expect_error(conn, errors.InsufficientPrivilege, lambda: act(
        "alice", "insert into storage.objects (bucket_id, name) values ('tenant-files', %s)",
        (f"{tenant_b}/dropped.pdf",)))


# --- roles outside the app ---------------------------------------------------

def test_anon_has_no_access(conn):
    for sql in ("select * from public.projects", "select * from public.tenants",
                "select private.tenant_ids()", "select public.create_tenant('x', 'xyz')"):
        with pytest.raises(errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("set local role anon")
                conn.execute(sql)


def test_table_owner_is_filtered_by_forced_rls(conn):
    # A backend that connects as the table owner (common with ORMs) must not skip the policies.
    conn.execute("alter table public.projects owner to app_owner")
    conn.execute("set local role app_owner")
    assert conn.execute("select count(*) from public.projects").fetchone() == (0,)


def test_create_tenant_makes_the_caller_owner(act):
    tenant = act("nora", "select public.create_tenant('Nora Co', 'nora-co')")[0][0]
    assert act("nora", "select role from public.memberships where tenant_id = %s", (tenant,)) == [("owner",)]
    assert act("alice", "select count(*) from public.tenants where id = %s", (tenant,)) == [(0,)]
