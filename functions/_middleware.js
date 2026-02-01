export async function onRequest(context) {
  const url = new URL(context.request.url);
  const path = url.pathname;

  // 1. PUBLIEKE ROUTES
  if (
    path === '/login' || 
    path === '/login.html' || 
    path === '/api/login' || 
    path === '/api/mfa-verify-login' || 
    path.includes('.')
  ) {
    return context.next();
  }

  // 2. CHECK COOKIE
  const cookie = context.request.headers.get('Cookie');
  const sessionKey = cookie?.match(/session_id=([^;]+)/)?.[1];

  if (!sessionKey) return Response.redirect(`${url.origin}/login.html`, 302);

  // 3. HAAL SESSIE OP
  const session = await context.env.MY_DB.prepare('SELECT * FROM sessions WHERE id = ?').bind(sessionKey).first();
  
  if (!session) {
    return logoutAndRedirect(url.origin);
  }

  // 4. CHECK TIJDSLIMIET (15 Minuten = 900.000 ms)
  const FIFTEEN_MINUTES = 15 * 60 * 1000;
  const now = Date.now();
  
  // Als last_active leeg is (oude sessies), gebruiken we created_at, of anders 0
  const lastActive = session.last_active || session.created_at || 0;

  if (now - lastActive > FIFTEEN_MINUTES) {
    // TE LANG INACTIEF: Verwijder sessie uit DB en stuur naar login
    await context.env.MY_DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionKey).run();
    return logoutAndRedirect(url.origin);
  }

  // 5. CHECK MFA STATUS
  if (session.status === 'pending_mfa') {
     return Response.redirect(`${url.origin}/login.html?mfa=needed`, 302);
  }

  // 6. ALLES OK? UPDATE TIJD & DOORGAAN
  // We updaten de 'last_active' tijd zodat de klok weer op 0 staat
  // We doen dit "fire and forget" (zonder await) zodat de gebruiker niet hoeft te wachten op de database
  context.env.MY_DB.prepare('UPDATE sessions SET last_active = ? WHERE id = ?').bind(now, sessionKey).run();

  // Haal user op voor de applicatie
  context.data.user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE id = ?').bind(session.user_id).first();
  
  return context.next();
}

// Hulpfunctie om netjes uit te loggen (cookie wissen)
function logoutAndRedirect(origin) {
  return new Response(null, {
    status: 302,
    headers: {
      'Location': `${origin}/login.html`,
      'Set-Cookie': 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT' 
    }
  });
}