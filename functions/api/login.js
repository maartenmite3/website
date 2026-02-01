export async function onRequestPost(context) {
  const { username, password } = await context.request.json();

  // Zoek gebruiker
  const user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE username = ? AND password = ?')
    .bind(username, password)
    .first();

  if (!user) {
    return new Response('Ongeldig', { status: 401 });
  }

  // Maak unieke sessie ID (simpel random nummer)
  const sessionId = crypto.randomUUID();
  await context.env.MY_DB.prepare('INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)')
    .bind(sessionId, user.id, Date.now())
    .run();

  // Zet cookie en stuur OK
  return new Response('OK', {
    headers: {
      'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Strict`,
    },
  });
}
