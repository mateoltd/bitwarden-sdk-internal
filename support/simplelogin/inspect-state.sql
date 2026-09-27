\pset pager off
\echo 'users'
SELECT id, email, activated, disabled, lifetime, default_mailbox_id
FROM users
ORDER BY id;

\echo 'public domains'
SELECT id, domain, premium_only, hidden, use_as_reverse_alias
FROM public_domain
ORDER BY id;

\echo 'aliases'
SELECT id, user_id, email, enabled, pinned, note, delete_on
FROM alias
ORDER BY id;

\echo 'contacts and reverse aliases'
SELECT c.id, c.alias_id, c.website_email, c.reply_email, c.block_forward
FROM contact c
ORDER BY c.id;

\echo 'API key metadata (codes intentionally omitted)'
SELECT id, user_id, name, last_used, times
FROM api_key
ORDER BY id;
