export async function onRequest(context) {
  // 1. Haal sessie ID uit cookie
  const cookie = context.request.headers.get('Cookie');
  const sessionKey = cookie?.match(/session_id=([^;]+)/)?.[1];

  // 2. Verwijder uit database als er een ID is
  if (sessionKey) {
    await context.env.MY_DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionKey).run();
  }

  // 3. Verwijder cookie bij de gebruiker
  return new Response('Uitgelogd', {
    headers: {
      'Set-Cookie': `session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      'Location': '/login.html'
    },
    status: 302
  });
}