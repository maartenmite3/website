export async function onRequest(context) {
  const url = new URL(context.request.url);
  const path = url.pathname;

  // 1. PUBLIEKE ROUTES (Iedereen mag hier komen)
  if (
    path === '/login' || 
    path === '/login.html' || 
    path === '/api/login' || 
    path === '/api/mfa-verify-login'
  ) {
    return context.next();
  }

  // 2. STATISCHE BESTANDEN (Plaatjes, CSS, JS mogen door, MAAR HTML NIET!)
  // We checken nu specifiek op extensies die veilig zijn.
  const publicExtensions = ['.css', '.js', '.png', '.jpg', '.ico', '.svg', '.json'];
  if (publicExtensions.some(ext => path.endsWith(ext))) {
    return context.next();
  }

  // 3. CHECK SESSIE (Voor al het andere: HTML pages, API calls, etc)
  const cookie = context.request.headers.get('Cookie');
  const sessionKey = cookie?.match(/session_id=([^;]+)/)?.[1];

  if (!sessionKey) return logoutAndRedirect(url.origin);

  // 4. CHECK DB
  const session = await context.env.MY_DB.prepare('SELECT * FROM sessions WHERE id = ?').bind(sessionKey).first();
  if (!session) return logoutAndRedirect(url.origin);

  // 5. TIMEOUT CHECK (15 min)
  const FIFTEEN_MINUTES = 15 * 60 * 1000;
  const now = Date.now();
  const lastActive = session.last_active || session.created_at || 0;

  if (now - lastActive > FIFTEEN_MINUTES) {
    await context.env.MY_DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionKey).run();
    return logoutAndRedirect(url.origin);
  }

  // 6. UPDATE TIJD & DOORGAAN
  context.env.MY_DB.prepare('UPDATE sessions SET last_active = ? WHERE id = ?').bind(now, sessionKey).run();
  
  // Haal user op
  context.data.user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE id = ?').bind(session.user_id).first();
  
  return context.next();
}

function logoutAndRedirect(origin) {
  return new Response(null, {
    status: 302,
    headers: {
      'Location': `${origin}/login.html`,
      'Set-Cookie': 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT' 
    }
  });
}