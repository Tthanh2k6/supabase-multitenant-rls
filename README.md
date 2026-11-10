# supabase-multitenant-rls

A reference migration and test suite for tenant isolation in a shared Postgres schema on Supabase: many customers (tenants) in the same tables, separated by Row Level Security.

It is a small, tested pattern to copy, not a product. There is no UI.

## What the migration does

- Every tenant-owned row has `tenant_id`, and every table has RLS enabled.
- Tenant data tables use `FORCE ROW LEVEL SECURITY`, so a backend that connects as the table owner (an ORM using the `postgres` user, for example) is filtered too.
- Membership checks run in `SECURITY DEFINER` helpers in a `private` schema that the API does not expose, with `search_path = ''`, executable only by `authenticated`.
- Child rows reference their parent with `(id, tenant_id)`, so a document in tenant A cannot point at a project in tenant B, even though foreign key checks bypass RLS.
- Roles (`owner`, `admin`, `member`) live in a `memberships` table. Nothing is read from `user_metadata`, which users can edit themselves.
- New tenants are created through `create_tenant()`, which makes the caller the owner in the same transaction. There is no INSERT policy on `tenants`.
- Storage: one private bucket, files stored under `<tenant_id>/...`, with policies on `storage.objects` that check the first folder.
- `anon` gets no table grants at all.

File: [`supabase/migrations/20261110000000_tenancy.sql`](supabase/migrations/20261110000000_tenancy.sql)

## What the tests prove

[`tests/test_isolation.py`](tests/test_isolation.py) signs in as real users (by setting `request.jwt.claims` the way PostgREST does) and tries to cross the boundary:

| Attempt | Expected |
| :--- | :--- |
| List projects, documents, tenants | Only your tenant's rows |
| Member of two tenants | Sees both |
| Read another tenant's row by id | Empty result |
| Insert a row with another tenant's `tenant_id` | `42501` (RLS) |
| Update your row's `tenant_id` to another tenant | `42501` (RLS `WITH CHECK`) |
| Update or delete another tenant's rows | 0 rows affected |
| Attach a document to another tenant's project | `23503` (composite foreign key) |
| Member adds a member, or claims `admin` in `user_metadata` | `42501` |
| Owner adds a member to another tenant, or hands out `owner` | `42501` |
| Read or upload another tenant's Storage files | Hidden / `42501` |
| `anon` reads tables, calls helpers or `create_tenant` | Permission denied |
| Table owner role without a matching policy | 0 rows (forced RLS) |

CI runs the tests on PostgreSQL 15 (the Supabase default), then runs [supabase-rls-check](https://github.com/Tthanh2k6/supabase-rls-check) v0.5.0 on the migrated schema and fails on any finding, Low included. As of 11 Nov 2026 it reports 0 findings.

## Run it

Locally, against any PostgreSQL 15+ server where your user can create databases:

```bash
python -m pip install -r requirements-dev.txt
DATABASE_URL=postgresql://postgres@127.0.0.1:5432/postgres python -m pytest -v
```

The tests create a throwaway database, load [`tests/supabase_stub.sql`](tests/supabase_stub.sql) (a minimal stand-in for Supabase's `auth` and `storage` schemas and roles), apply the migration, and drop the database at the end.

On a Supabase project, apply only the migration (`supabase db push`, or paste it into the SQL editor). Do not run the stub there.

## Limits

- The stub imitates `auth.uid()`, `auth.jwt()` and `storage.foldername()`; behaviour on a real Supabase project should be confirmed on a staging project before you rely on it.
- `memberships` is not forced on purpose: the helpers read it as the owner, and forcing it would make them recurse through its own policies.
- Column-level secrets (salary, cost price, API tokens) need a separate table or a `security_invoker` view. RLS filters rows, not columns.
- Subdomain routing, invitations by email and billing are out of scope.

## License

MIT
