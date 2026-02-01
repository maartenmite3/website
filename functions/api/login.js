import bcrypt from 'bcryptjs';

export async function onRequestPost(context) {
  try {
      const { username, password } = await context.request.json();

      // 1. Zoek de gebruiker
      const user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE username = ?')
        .bind(username)
        .first();

      if (!user) return new Response('Ongeldig', { status: 401 });

      // 2. Controleer wachtwoord (Hash of tijdelijk Plain text)
      let passwordMatch = false;
      if (user.password.startsWith('$2a$')) {
          passwordMatch = await bcrypt.compare(password, user.password);
      } else {
          passwordMatch = (user.password === password);
      }

      if (!passwordMatch) return new Response('Ongeldig', { status: 401 });

      // 3. Maak sessie aan
      const sessionId = crypto.randomUUID();
      const status = user.mfa_enabled ? 'pending_mfa' : 'active';
      const now = Date.now();

      await context.env.MY_DB.prepare('INSERT INTO sessions (id, user_id, created_at, status, last_active) VALUES (?, ?, ?, ?, ?)')
        .bind(sessionId, user.id, now, status, now)
        .run();

      // --- LOG DE LOGIN ---
      // We gebruiken hier 'user.id' omdat context.data.user nog leeg is (je bent immers nog aan het inloggen)
      await context.env.MY_DB.prepare(
          "INSERT INTO logs (user_id, username, action, details, created_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(user.id, user.username, 'LOGIN', 'Succesvol ingelogd', Date.now()).run();
      // --------------------

      return new Response(JSON.stringify({ mfa_required: user.mfa_enabled === 1 }), {
        headers: {
          'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Strict`,
          'Content-Type': 'application/json'
        },
      });

  } catch (err) {
      return new Response('Server fout: ' + err.message, { status: 500 });
  }
}