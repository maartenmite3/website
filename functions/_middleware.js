export async function onRequest(context) {
  const url = new URL(context.request.url);
  const path = url.pathname;

  // 1. PUBLIEKE ROUTES
  if (
    path === '/login' || 
    path === '/login.html' || 
    path === '/api/login' || 
    path === '/api/mfa-verify-login' || // NIEUW: Hier checken we de code
    path.includes('.')
  ) {
    return context.next();
  }

  // 2. CHECK COOKIE
  const cookie = context.request.headers.get('Cookie');
  const sessionKey = cookie?.match(/session_id=([^;]+)/)?.[1];

  if (!sessionKey) return Response.redirect(`${url.origin}/login.html`, 302);

  // 3. CHECK DATABASE & STATUS
  const session = await context.env.MY_DB.prepare('SELECT * FROM sessions WHERE id = ?').bind(sessionKey).first();
  
  if (!session) {
    // Sessie bestaat niet -> Wegwezen
    return new Response(null, { status: 302, headers: { 'Location': '/login.html', 'Set-Cookie': 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT' }});
  }

  // NIEUW: Als de sessie wacht op MFA, en we zitten niet op een API, stuur terug naar login
  if (session.status === 'pending_mfa') {
     // We sturen een signaal dat de frontend kan oppikken om het 2e scherm te tonen
     return Response.redirect(`${url.origin}/login.html?mfa=needed`, 302);
  }

  // 4. HAAL USER OP
  context.data.user = await context.env.MY_DB.prepare('SELECT * FROM users WHERE id = ?').bind(session.user_id).first();
  return context.next();
}