# Supabase Security Configuration

This guide explains how to configure your Supabase database for read-only access using the anon key.

## Overview

The anon key is designed to be public and used in client-side applications. Security is enforced through Row Level Security (RLS) policies, not by keeping the key secret.

## Setting Up Read-Only Access

### 1. Enable RLS on All Tables

Run the SQL commands in `supabase-rls-policies.sql` in your Supabase SQL Editor:

1. Go to your Supabase project dashboard
2. Navigate to SQL Editor
3. Create a new query
4. Copy and paste the contents of `supabase-rls-policies.sql`
5. Click "Run"

### 2. Verify RLS is Enabled

You can verify RLS is enabled by running:

```sql
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public' 
AND tablename IN ('ipsws', 'devices', 'ipsw_devices',
                  'entitlement_keys', 'entitlement_values',
                  'paths', 'entitlements');
```

All tables should show `rowsecurity = true`.

### 3. Use a Dedicated Writer for Automation

The website should only use the public anon key. GitHub Actions should use a dedicated PostgreSQL login role stored in repository secrets, not the `postgres` owner password and never a browser-exposed key.

Create a writer role with a generated password and grant it only the permissions needed by `ipsw ent --replace`:

```sql
CREATE ROLE entitlements_writer WITH LOGIN PASSWORD '<generated-long-password>';

GRANT USAGE ON SCHEMA public TO entitlements_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  ipsws,
  devices,
  ipsw_devices,
  entitlement_keys,
  entitlement_values,
  paths,
  entitlements
TO entitlements_writer;

GRANT USAGE, SELECT, UPDATE ON SEQUENCE
  entitlement_keys_id_seq,
  entitlement_values_id_seq,
  paths_id_seq,
  entitlements_id_seq
TO entitlements_writer;
```

Set `.github/workflows/update-entitlements-db.yml` secrets so `SUPABASE_USER=entitlements_writer` and `SUPABASE_PASSWORD` is that generated password. Keep `SUPABASE_HOST` pointed at the project database host and keep SSL required.

### 4. Test Read-Only Access

Test that the anon key can only read data:

```javascript
// This should work (SELECT)
const { data, error } = await supabase
  .from('entitlement_keys')
  .select('*')
  .limit(1);

// This should fail (INSERT)
const { error: insertError } = await supabase
  .from('entitlement_keys')
  .insert({ /* some data */ });
// Expected: Error - permission denied

// This should fail (UPDATE)
const { error: updateError } = await supabase
  .from('entitlement_keys')
  .update({ /* some data */ })
  .eq('id', 1);
// Expected: Error - permission denied

// This should fail (DELETE)
const { error: deleteError } = await supabase
  .from('entitlement_keys')
  .delete()
  .eq('id', 1);
// Expected: Error - permission denied
```

## How RLS Policies Work

1. **When RLS is enabled**: All access is denied by default
2. **Policies grant specific permissions**: We only create SELECT policies for the browser roles
3. **No policy = Access denied**: Since we don't create INSERT/UPDATE/DELETE policies, those operations are automatically denied

## Writer Credentials for Automation

The GitHub Actions writer credentials are direct PostgreSQL credentials and must be kept secret. Prefer a dedicated role such as `entitlements_writer` over the project owner password. Service role or secret API keys bypass RLS and must never be shipped to the website.

## Important Security Notes

1. **The anon key is safe to expose** - It's designed for public use
2. **RLS policies are your security layer** - They control what operations are allowed
3. **Always test your policies** - Verify that write operations fail with the anon key
4. **Monitor usage** - Check Supabase logs for any unexpected write attempts
5. **Do not expose writer credentials** - Keep PostgreSQL passwords, service role keys, and secret keys in GitHub Actions or backend-only secret stores

## Checking Current Policies

To see all active RLS policies:

```sql
SELECT schemaname, tablename, policyname, cmd, roles, qual
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;
```

## Removing Write Access (If Needed)

If you accidentally created policies that allow write access, remove them:

```sql
-- Example: Remove a policy that allows INSERT
DROP POLICY IF EXISTS "policy_name" ON table_name;
```

## Additional Security Recommendations

1. **Enable email confirmations** for auth (if using Supabase Auth)
2. **Set up rate limiting** in Supabase dashboard
3. **Monitor API usage** for unusual patterns
4. **Use environment variables** for the anon key in development
5. **Rotate keys periodically** if you suspect compromise

## Summary

With these RLS policies in place:
- ✅ Browser clients can READ all entitlement data
- ❌ Browser clients CANNOT write, update, or delete any data
- ✅ Your GitHub Actions writer role can still update the entitlement tables
- ✅ The anon key is safe to include in client-side code
