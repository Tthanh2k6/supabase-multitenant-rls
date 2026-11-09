-- Multi-tenant data model on one shared schema.
--
-- Rules this migration follows:
--   * Every tenant-owned row carries tenant_id, and every table has RLS enabled.
--   * Tenant data tables use FORCE ROW LEVEL SECURITY, so a backend that connects as the
--     table owner (an ORM using the postgres user, for example) is filtered too.
--   * Membership checks live in SECURITY DEFINER helpers in a non-exposed schema, with an
--     empty search_path, and only `authenticated` may execute them.
--   * Child rows reference their parent with (id, tenant_id), so a row in tenant A cannot
--     point at a parent in tenant B even through a foreign key.
--   * Roles come from the memberships table, never from user-editable user_metadata.
--   * anon gets nothing.

create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 120),
  slug text not null unique check (slug ~ '^[a-z0-9-]{3,40}$'),
  created_at timestamptz not null default now()
);

create table public.memberships (
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null check (role in ('owner', 'admin', 'member')),
  created_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);
create index memberships_user_id_idx on public.memberships (user_id);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  name text not null check (char_length(name) between 1 and 200),
  created_by uuid default auth.uid() references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  unique (id, tenant_id)
);
create index projects_tenant_id_idx on public.projects (tenant_id);

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  project_id uuid not null,
  title text not null check (char_length(title) between 1 and 300),
  created_by uuid default auth.uid() references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  -- The composite key makes "document in tenant A, project in tenant B" impossible.
  foreign key (project_id, tenant_id) references public.projects (id, tenant_id) on delete cascade
);
create index documents_tenant_id_idx on public.documents (tenant_id);
create index documents_project_id_idx on public.documents (project_id);

-- ---------------------------------------------------------------------------
-- Helpers (not exposed through the API: the private schema is not in PostgREST's search path)
-- ---------------------------------------------------------------------------

-- Tenants the signed-in user belongs to. Reads only the caller's own membership rows.
create function private.tenant_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select m.tenant_id
  from public.memberships m
  where m.user_id = (select auth.uid())
$$;

-- Does the signed-in user hold one of these roles in this tenant?
create function private.has_role(p_tenant_id uuid, p_roles text[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.memberships m
    where m.tenant_id = p_tenant_id
      and m.user_id = (select auth.uid())
      and m.role = any (p_roles)
  )
$$;

revoke all on function private.tenant_ids() from public;
revoke all on function private.has_role(uuid, text[]) from public;
grant execute on function private.tenant_ids() to authenticated;
grant execute on function private.has_role(uuid, text[]) to authenticated;

-- Creating a tenant goes through this function so the creator becomes its owner in the
-- same transaction. There is deliberately no INSERT policy on tenants.
create function public.create_tenant(p_name text, p_slug text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := (select auth.uid());
  v_tenant uuid;
begin
  if v_user is null then
    raise exception 'not signed in' using errcode = '42501';
  end if;
  insert into public.tenants (name, slug) values (p_name, p_slug) returning id into v_tenant;
  insert into public.memberships (tenant_id, user_id, role) values (v_tenant, v_user, 'owner');
  return v_tenant;
end;
$$;

revoke all on function public.create_tenant(text, text) from public, anon;
grant execute on function public.create_tenant(text, text) to authenticated;

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------

alter table public.tenants enable row level security;
alter table public.memberships enable row level security;
alter table public.projects enable row level security;
alter table public.documents enable row level security;

-- Tenant data: the owner is filtered too. memberships stays unforced on purpose: the
-- SECURITY DEFINER helpers above run as the owner and must read it without recursing.
alter table public.tenants force row level security;
alter table public.projects force row level security;
alter table public.documents force row level security;

-- tenants
create policy tenants_select on public.tenants
  for select to authenticated
  using (id in (select private.tenant_ids()));

create policy tenants_update on public.tenants
  for update to authenticated
  using (private.has_role(id, array['owner', 'admin']))
  with check (private.has_role(id, array['owner', 'admin']));

-- memberships: you see your own rows; owners and admins see and manage their tenant's rows.
create policy memberships_select on public.memberships
  for select to authenticated
  using (
    user_id = (select auth.uid())
    or private.has_role(tenant_id, array['owner', 'admin'])
  );

create policy memberships_insert on public.memberships
  for insert to authenticated
  with check (
    private.has_role(tenant_id, array['owner', 'admin'])
    and role <> 'owner'
  );

create policy memberships_delete on public.memberships
  for delete to authenticated
  using (
    private.has_role(tenant_id, array['owner', 'admin'])
    and role <> 'owner'
  );

-- projects
create policy projects_select on public.projects
  for select to authenticated
  using (tenant_id in (select private.tenant_ids()));

create policy projects_insert on public.projects
  for insert to authenticated
  with check (tenant_id in (select private.tenant_ids()));

create policy projects_update on public.projects
  for update to authenticated
  using (tenant_id in (select private.tenant_ids()))
  with check (tenant_id in (select private.tenant_ids()));

create policy projects_delete on public.projects
  for delete to authenticated
  using (private.has_role(tenant_id, array['owner', 'admin']));

-- documents
create policy documents_select on public.documents
  for select to authenticated
  using (tenant_id in (select private.tenant_ids()));

create policy documents_insert on public.documents
  for insert to authenticated
  with check (tenant_id in (select private.tenant_ids()));

create policy documents_update on public.documents
  for update to authenticated
  using (tenant_id in (select private.tenant_ids()))
  with check (tenant_id in (select private.tenant_ids()));

create policy documents_delete on public.documents
  for delete to authenticated
  using (tenant_id in (select private.tenant_ids()));

-- ---------------------------------------------------------------------------
-- Grants: nothing for anon
-- ---------------------------------------------------------------------------

revoke all on public.tenants, public.memberships, public.projects, public.documents from anon, public;
grant select, update on public.tenants to authenticated;
grant select, insert, delete on public.memberships to authenticated;
grant select, insert, update, delete on public.projects, public.documents to authenticated;

-- ---------------------------------------------------------------------------
-- Storage: one private bucket, files live under "<tenant_id>/..."
-- ---------------------------------------------------------------------------

insert into storage.buckets (id, name, public)
values ('tenant-files', 'tenant-files', false)
on conflict (id) do nothing;

create policy tenant_files_select on storage.objects
  for select to authenticated
  using (
    bucket_id = 'tenant-files'
    and (storage.foldername(name))[1] in (select t::text from private.tenant_ids() as t)
  );

create policy tenant_files_insert on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'tenant-files'
    and (storage.foldername(name))[1] in (select t::text from private.tenant_ids() as t)
  );

create policy tenant_files_update on storage.objects
  for update to authenticated
  using (
    bucket_id = 'tenant-files'
    and (storage.foldername(name))[1] in (select t::text from private.tenant_ids() as t)
  )
  with check (
    bucket_id = 'tenant-files'
    and (storage.foldername(name))[1] in (select t::text from private.tenant_ids() as t)
  );

create policy tenant_files_delete on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'tenant-files'
    and (storage.foldername(name))[1] in (select t::text from private.tenant_ids() as t)
  );
