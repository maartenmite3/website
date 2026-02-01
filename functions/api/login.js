export async function onRequestPost(context) {
  const { username, password } = await context.request.json();

  const user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE username = ? AND password = ?').bind(username, password).first();

  if (!user) return new Response('Ongeldig', { status: 401 });

  const sessionId = crypto.randomUUID();
  
  // LOGICA: Als MFA aanstaat, is de status 'pending_mfa', anders 'active'
  const status = user.mfa_enabled ? 'pending_mfa' : 'active';

  await context.env.MY_DB.prepare('INSERT INTO sessions (id, user_id, created_at, status) VALUES (?, ?, ?, ?)')
    .bind(sessionId, user.id, Date.now(), status)
    .run();

  // We sturen terug of MFA nodig is
  return new Response(JSON.stringify({ mfa_required: user.mfa_enabled === 1 }), {
    headers: {
      'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Strict`,
      'Content-Type': 'application/json'
    },
  });
}