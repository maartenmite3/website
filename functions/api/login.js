import bcrypt from 'bcryptjs';

export async function onRequestPost(context) {
  const { username, password } = await context.request.json();

  // 1. Zoek de gebruiker ALLEEN op naam
  const user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE username = ?')
    .bind(username)
    .first();

  if (!user) return new Response('Ongeldig', { status: 401 });

  // 2. Controleer of het wachtwoord klopt met de hash
  // (We checken voor de zekerheid ook of er nog een oud plain-text wachtwoord staat voor backward compatibility tijdens testen)
  let passwordMatch = false;
  
  if (user.password.startsWith('$2a$')) {
      // Het is een hash
      passwordMatch = await bcrypt.compare(password, user.password);
  } else {
      // Het is nog oude clear text (tijdelijk, voor de migratie)
      passwordMatch = (user.password === password);
  }

  if (!passwordMatch) return new Response('Ongeldig', { status: 401 });

  // 3. Maak sessie (de rest blijft hetzelfde)
  const sessionId = crypto.randomUUID();
  const status = user.mfa_enabled ? 'pending_mfa' : 'active';
  const now = Date.now();

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