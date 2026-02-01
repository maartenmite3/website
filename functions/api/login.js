export async function onRequestPost(context) {
  const { username, password } = await context.request.json();

  const user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE username = ? AND password = ?').bind(username, password).first();

  if (!user) return new Response('Ongeldig', { status: 401 });

  const sessionId = crypto.randomUUID();
  const status = user.mfa_enabled ? 'pending_mfa' : 'active';
  const now = Date.now();

  // UPDATE: We voegen 'last_active' toe aan de insert
  await context.env.MY_DB.prepare('INSERT INTO sessions (id, user_id, created_at, status, last_active) VALUES (?, ?, ?, ?, ?)')
    .bind(sessionId, user.id, now, status, now)
    .run();

  return new Response(JSON.stringify({ mfa_required: user.mfa_enabled === 1 }), {
    headers: {
      'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Strict`,
      'Content-Type': 'application/json'
    },
  });
}