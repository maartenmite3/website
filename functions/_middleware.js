export async function onRequest(context) {
  const url = new URL(context.request.url);
  
  // 1. Deze paden mag iedereen zien (anders kom je nooit binnen)
  if (url.pathname === '/login.html' || url.pathname.startsWith('/api/')) {
    return context.next();
  }

  // 2. Check of er een sessie-cookie is
  const cookie = context.request.headers.get('Cookie');
  const sessionKey = cookie?.match(/session_id=([^;]+)/)?.[1];

  if (!sessionKey) {
    // Geen sessie? Redirect naar login
    return Response.redirect(`${url.origin}/login.html`, 302);
  }

  // 3. Check in database of sessie geldig is
  const session = await context.env.MY_DB.prepare('SELECT * FROM sessions WHERE id = ?').bind(sessionKey).first();
  
  if (!session) {
    // Ongeldige sessie? Redirect naar login
    return Response.redirect(`${url.origin}/login.html`, 302);
  }

  // 4. Alles oké? Sla user info op voor later en ga door
  context.data.user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE id = ?').bind(session.user_id).first();
  return context.next();
}
