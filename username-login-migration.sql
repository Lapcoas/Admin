-- RaevYoU Admin: username + password login (already applied to project qsxlvufosgsdabsykxjx)
-- Safe to rerun. Does not touch reviews, messages, conversations, or existing content.
alter table public.admins add column if not exists username text;

update public.admins
set username = 'admin_' || substr(replace(user_id::text, '-', ''), 1, 12)
where username is null or btrim(username) = '';

create unique index if not exists admins_username_lower_uidx
  on public.admins (lower(username));

alter table public.admins drop constraint if exists admins_username_format_check;
alter table public.admins add constraint admins_username_format_check
  check (username ~ '^[a-z0-9_.-]{3,24}$');

drop function if exists public.claim_owner(text, text);
drop function if exists public.redeem_invite(text, text);

create or replace function public.claim_owner(p_code text, p_name text, p_username text)
returns void language plpgsql security definer set search_path = public as $$
declare v text; u text;
begin
  if auth.uid() is null or public.is_anon_user() then raise exception 'not_allowed'; end if;
  u := lower(trim(p_username));
  if u !~ '^[a-z0-9_.-]{3,24}$' then raise exception 'invalid_username'; end if;
  if exists (select 1 from public.admins where lower(username) = u) then raise exception 'username_taken'; end if;
  if exists (select 1 from public.admins where role = 'owner') then raise exception 'owner_exists'; end if;
  select value into v from public.app_config where key = 'owner_setup_code';
  if v is null or v = '' or v like 'CHANGE-ME%' or p_code is distinct from v then raise exception 'bad_code'; end if;
  insert into public.admins (user_id, email, username, display_name, role)
  values (auth.uid(), coalesce(auth.jwt() ->> 'email', ''), u, left(trim(p_name), 40), 'owner');
end $$;

create or replace function public.redeem_invite(p_code text, p_name text, p_username text)
returns void language plpgsql security definer set search_path = public as $$
declare inv public.invites; u text;
begin
  if auth.uid() is null or public.is_anon_user() then raise exception 'not_allowed'; end if;
  u := lower(trim(p_username));
  if u !~ '^[a-z0-9_.-]{3,24}$' then raise exception 'invalid_username'; end if;
  if exists (select 1 from public.admins where lower(username) = u) then raise exception 'username_taken'; end if;
  if exists (select 1 from public.admins where user_id = auth.uid()) then raise exception 'already_admin'; end if;
  select * into inv from public.invites
    where code = upper(trim(p_code)) and used_by is null and expires_at > now() for update;
  if not found then raise exception 'bad_code'; end if;
  insert into public.admins (user_id, email, username, display_name, role)
  values (auth.uid(), coalesce(auth.jwt() ->> 'email', ''), u, left(trim(p_name), 40), 'admin');
  update public.invites set used_by = auth.uid(), used_at = now() where code = inv.code;
end $$;

revoke all on function public.claim_owner(text, text, text), public.redeem_invite(text, text, text) from public, anon;
grant execute on function public.claim_owner(text, text, text), public.redeem_invite(text, text, text) to authenticated;
