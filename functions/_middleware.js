export async function onRequest(context) {
  const url = new URL(context.request.url);
  const path = url.pathname;

  // 1. UITZONDERINGEN: Deze paden mag IEDEREEN zien.
  // We checken nu op '/login', '/login.html' en alles wat start met '/api/'
  // Ook slaan we bestanden over die een punt bevatten (zoals style.css, favicon.ico), 
  // zodat de browser niet vastloopt op plaatjes.
  if (
    path === '/login' || 
    path === '/login.html' || 
    path.startsWith('/api/') ||
    path.includes('.') // Negeer bestanden met extensies (plaatjes, css, etc)
  ) {
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
  // We gebruiken hier user_id selectie om database data te sparen
  const session = await context.env.MY_DB.prepare('SELECT user_id FROM sessions WHERE id = ?').bind(sessionKey).first();
  
  if (!session) {
    // Wel een cookie, maar sessie niet gevonden in DB? (Bijv. verlopen) -> Redirect
    // We verwijderen ook meteen de foute cookie voor de zekerheid
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/login.html',
        'Set-Cookie': 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT' 
      }
    });
  }

  // 4. Alles oké? Haal user op
  context.data.user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE id = ?').bind(session.user_id).first();
  return context.next();
}
