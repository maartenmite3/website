export async function onRequest(context) {
  const url = new URL(context.request.url);
  const path = url.pathname;

  // 1. PUBLIEKE ROUTES (Iedereen mag hier komen)
  // - De root login pagina
  // - Het bestand login.html
  // - De API om in te loggen (anders kun je nooit inloggen)
  // - Bestanden met een punt (zoals plaatjes, css, js)
  if (
    path === '/login' || 
    path === '/login.html' || 
    path === '/api/login' ||   // <--- BELANGRIJKE WIJZIGING: Alleen deze API is publiek
    path.includes('.')
  ) {
    return context.next();
  }

  // 2. VOOR AL HET ANDERE: Check sessie cookie
  const cookie = context.request.headers.get('Cookie');
  const sessionKey = cookie?.match(/session_id=([^;]+)/)?.[1];

  if (!sessionKey) {
    // Geen sessie? Redirect naar login
    return Response.redirect(`${url.origin}/login.html`, 302);
  }

  // 3. Check in database of sessie geldig is
  const session = await context.env.MY_DB.prepare('SELECT user_id FROM sessions WHERE id = ?').bind(sessionKey).first();
  
  if (!session) {
    // Sessie niet gevonden of verlopen? Redirect naar login en wis cookie
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/login.html',
        'Set-Cookie': 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT' 
      }
    });
  }

  // 4. Sessie gevonden! Haal gebruiker op en stop in context
  context.data.user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE id = ?').bind(session.user_id).first();
  
  // Ga door naar de gevraagde pagina/api
  return context.next();
}