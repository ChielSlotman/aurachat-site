-- 001_codes_active_unique.sql

-- 1) Optional: normalize any existing gmail rows
-- UPDATE public.codes
--   SET note = regexp_replace(split_part(lower(note), '@', 1), '\.', '', 'g') || '@gmail.com'
-- WHERE lower(note) ~ '@(gmail\.com|googlemail\.com)$';

-- 2) Drop any old "active unique" index that isn't scoped to email
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'codes_active_unique') THEN
    EXECUTE 'DROP INDEX codes_active_unique';
  END IF;
END$$;

-- 3) Create the intended index: one active code per email (using note as email)
CREATE UNIQUE INDEX codes_active_unique
  ON public.codes (note)
  WHERE status = 'active';
