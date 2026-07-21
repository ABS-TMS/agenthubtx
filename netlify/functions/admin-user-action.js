// Netlify Function: admin-user-action
// Requires elevated permissions to ban/unban a Supabase Auth user.
// Verifies the CALLER is the broker (via their own session token) before
// using the service role key to actually perform the action.

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://tjdxnmukjraljvjprolk.supabase.co';
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_EMAIL = 'mike@urocketrealty.com';

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  try {
    const { action, email, accessToken } = JSON.parse(event.body);

    if (!accessToken) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Missing session token' }) };
    }
    if (!['ban', 'unban'].includes(action)) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Invalid action' }) };
    }
    if (!email) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Missing email' }) };
    }

    // Verify the caller's identity using their own session token against the anon client
    const callerClient = createClient(SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
    const { data: userData, error: userError } = await callerClient.auth.getUser(accessToken);
    if (userError || !userData?.user || userData.user.email !== ADMIN_EMAIL) {
      return { statusCode: 403, body: JSON.stringify({ error: 'Not authorized' }) };
    }

    // Now use the service role client to actually find and ban/unban the target user
    const adminClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

    // Look up the user by email (admin API doesn't support direct email lookup, so list + filter)
    let targetUser = null;
    let page = 1;
    while (!targetUser) {
      const { data, error } = await adminClient.auth.admin.listUsers({ page, perPage: 200 });
      if (error) throw error;
      targetUser = data.users.find(u => u.email?.toLowerCase() === email.toLowerCase());
      if (targetUser || data.users.length < 200) break;
      page++;
    }

    if (!targetUser) {
      return { statusCode: 404, body: JSON.stringify({ error: 'No account found with that email' }) };
    }

    const banDuration = action === 'ban' ? '876000h' : 'none'; // ~100 years, or lift the ban
    const { error: updateError } = await adminClient.auth.admin.updateUserById(targetUser.id, {
      ban_duration: banDuration,
    });
    if (updateError) throw updateError;

    return { statusCode: 200, body: JSON.stringify({ success: true, action }) };
  } catch (err) {
    console.error('admin-user-action error:', err);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};
