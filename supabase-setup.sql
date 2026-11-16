-- น้องอยู่ไหน · ตั้งค่าฐานข้อมูล Supabase
-- วิธีใช้: Supabase → SQL Editor → New query → วางทั้งไฟล์นี้ → Run
-- รันซ้ำได้ ไม่ทำให้ข้อมูลเดิมหาย

-- 1) ผู้ดูแลระบบ
create table if not exists public.admins (
  uid uuid primary key,
  created_at timestamptz not null default now()
);
alter table public.admins enable row level security;
-- ไม่มี policy = แอปอ่าน/เขียนตารางนี้ตรงๆ ไม่ได้ ต้องผ่านฟังก์ชันด้านล่างเท่านั้น

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where uid = auth.uid());
$$;

create or replace function public.admin_exists() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins);
$$;

-- คนแรกที่กดจะได้เป็นผู้ดูแล หลังจากนั้นปิดอัตโนมัติ
create or replace function public.claim_admin() returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return false; end if;
  if exists (select 1 from public.admins) then
    return exists (select 1 from public.admins where uid = auth.uid());
  end if;
  insert into public.admins (uid) values (auth.uid());
  return true;
end $$;

grant execute on function public.is_admin(), public.admin_exists(), public.claim_admin() to anon, authenticated;

-- 2) ตารางข้อมูล (ทุกตารางหน้าตาเหมือนกัน: id, data, ใครเป็นคนสร้าง, เวลา)
do $$
declare t text;
begin
  foreach t in array array['posts','colonies','events','sightings','reports','updates','mod','photos'] loop
    execute format('create table if not exists public.%I (
      id text primary key,
      data jsonb not null default ''{}''::jsonb,
      by uuid default auth.uid(),
      created_at timestamptz not null default now()
    )', t);
    execute format('alter table public.%I enable row level security', t);
    -- ทุกคนอ่านได้ แม้ไม่ได้เข้าระบบ
    execute format('drop policy if exists "read all" on public.%I', t);
    execute format('create policy "read all" on public.%I for select using (true)', t);
    execute format('drop policy if exists "insert signed in" on public.%I', t);
    execute format('drop policy if exists "update own or admin" on public.%I', t);
    execute format('drop policy if exists "update signed in" on public.%I', t);
    execute format('drop policy if exists "delete own or admin" on public.%I', t);
    execute format('drop policy if exists "admin only" on public.%I', t);
  end loop;

  -- ลงข้อมูลได้เมื่อเข้าระบบแล้ว (รวมผู้ใช้แบบไม่ระบุตัวตน) และต้องเป็นชื่อตัวเอง
  foreach t in array array['posts','colonies','events','sightings','reports','updates','photos'] loop
    execute format('create policy "insert signed in" on public.%I for insert to authenticated with check (by = auth.uid())', t);
    execute format('create policy "delete own or admin" on public.%I for delete to authenticated using (by = auth.uid() or public.is_admin())', t);
  end loop;

  -- แก้ได้เฉพาะคนที่สร้างหรือผู้ดูแล
  foreach t in array array['posts','events','sightings','reports','updates','photos'] loop
    execute format('create policy "update own or admin" on public.%I for update to authenticated using (by = auth.uid() or public.is_admin()) with check (by = auth.uid() or public.is_admin())', t);
  end loop;
end $$;

-- จุดแมวจรเป็นของชุมชน: ใครเข้าระบบแล้วก็อัปเดตการให้อาหาร/จำนวน/ทำหมันได้
create policy "update signed in" on public.colonies for update to authenticated using (true) with check (true);

-- การซ่อนโพสต์ (moderation): ผู้ดูแลเท่านั้น
create policy "admin only" on public.mod for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- 3) อัปเดตสด (realtime)
do $$
declare t text;
begin
  foreach t in array array['posts','colonies','events','sightings','reports','updates','mod'] loop
    begin
      execute format('alter publication supabase_realtime add table public.%I', t);
    exception when duplicate_object then null;
    end;
  end loop;
end $$;

-- เสร็จแล้ว อย่าลืมเปิด Anonymous sign-ins ที่ Authentication → Sign In / Providers
-- ถ้าเผลอเสียสิทธิ์ผู้ดูแล (เช่น ล้างข้อมูลเบราว์เซอร์): ดูรหัสผู้ใช้ใหม่ในหน้า "นักสืบของฉัน" แล้วรัน
--   insert into public.admins (uid) values ('รหัสผู้ใช้');

-- 4) วิดีโอ: เก็บใน Storage (ฟรี 1 GB) โฟลเดอร์ของแต่ละคน ไม่เกิน 25 MB ต่อไฟล์
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('videos', 'videos', true, 26214400, array['video/mp4','video/quicktime','video/webm'])
on conflict (id) do update set public = true, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "videos upload own folder" on storage.objects;
create policy "videos upload own folder" on storage.objects for insert to authenticated
  with check (bucket_id = 'videos' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "videos delete own or admin" on storage.objects;
create policy "videos delete own or admin" on storage.objects for delete to authenticated
  using (bucket_id = 'videos' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));
