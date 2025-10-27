-- Search for a username
SELECT
  convert_from(username, 'UTF8') AS username,
  convert_from(password, 'UTF8') AS password,
  domain_id
FROM public.logins
WHERE convert_from(username, 'UTF8') LIKE '%ehagi%'
LIMIT 50;