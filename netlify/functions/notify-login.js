// Receives a webhook call from Supabase (fired by a Postgres trigger on
// auth.users) when someone logs in for the first time ever, or logs back
// in after being Quiet/Never (per AgentHubTX's existing engagement
// buckets). Sends Mike a short email so he can catch the moment and send
// a quick "how's it going" check-in while it's fresh.
//
// Protected by a shared secret header (NOTIFY_WEBHOOK_SECRET) so only the
// Supabase trigger can call this -- not just anyone who finds the URL.

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const providedSecret = event.headers['x-notify-secret'];
  if (!providedSecret || providedSecret !== process.env.NOTIFY_WEBHOOK_SECRET) {
    return { statusCode: 401, body: 'Unauthorized' };
  }

  let payload;
  try {
    payload = JSON.parse(event.body);
  } catch (e) {
    return { statusCode: 400, body: 'Invalid JSON' };
  }

  const { name, email, reason } = payload;
  if (!email) {
    return { statusCode: 400, body: 'Missing email' };
  }

  const firstName = (name || '').trim().split(' ')[0] || 'They';
  const isFirstLogin = reason === 'first_login';

  const subject = isFirstLogin
    ? `🔔 ${name || email} just logged in for the first time`
    : `🔔 ${name || email} is back — first login in a while`;

  const suggestedLine = isFirstLogin
    ? `Hey ${firstName} — saw you just got in for the first time. What was your first impression? Anything jump out as useful, confusing, or missing?`
    : `Hey ${firstName} — good to see you back in there. Anything I can help with, or anything that's changed since you last looked around?`;

  const html = `
    <div style="font-family: Segoe UI, sans-serif; color: #444441; max-width: 480px;">
      <p style="font-size: 15px;"><strong>${escapeHtml(name || email)}</strong> ${isFirstLogin ? 'just logged into AgentHubTX for the first time.' : "just logged back into AgentHubTX after being quiet."}</p>
      <p style="font-size: 13px; color: #888780;">${escapeHtml(email)}</p>
      <div style="background: #F7F6F3; border-radius: 8px; padding: 14px 16px; margin: 16px 0; font-size: 14px;">
        <div style="color: #888780; font-size: 11px; text-transform: uppercase; font-weight: 700; margin-bottom: 6px;">Suggested check-in</div>
        <div>${escapeHtml(suggestedLine)}</div>
      </div>
      <p style="font-size: 12px; color: #888780;">This is a live-moment nudge, not a full report — toggle it off from invite-tracker.html any time it gets too noisy.</p>
    </div>
  `;

  try {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'AgentHubTX <noreply@agenthubtx.com>',
        to: ['mike@urocketrealty.com'],
        subject,
        html,
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error('Resend send failed:', errText);
      return { statusCode: 502, body: 'Email send failed' };
    }

    return { statusCode: 200, body: 'OK' };
  } catch (err) {
    console.error('notify-login error:', err);
    return { statusCode: 500, body: 'Internal error' };
  }
};

function escapeHtml(str) {
  return (str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
