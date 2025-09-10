-- Normalize emails to lowercase
UPDATE public.codes
SET note = LOWER(TRIM(note))
WHERE note IS NOT NULL;

-- Revoke older active codes per email (keep most recent)
WITH ranked AS (
  SELECT id,
         note,
         status,
         created_at,
         ROW_NUMBER() OVER (PARTITION BY note ORDER BY created_at DESC) AS rn
  FROM public.codes
  WHERE status = 'active'
)
UPDATE public.codes c
SET status = 'revoked', revoked_at = NOW()
FROM ranked r
WHERE c.id = r.id
  AND r.rn > 1;

-- Drop any pre-existing index with wrong definition
DROP INDEX IF EXISTS public.codes_active_unique;

-- Create the correct partial unique index (one active per email)
CREATE UNIQUE INDEX public.codes_active_unique
  ON public.codes (note)
  WHERE status = 'active';
