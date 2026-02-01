export async function onRequest(context) {
  // Verwijder cookie
  return new Response('Uitgelogd', {
    headers: {
      'Set-Cookie': `session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      'Location': '/login.html'
    },
    status: 302
  });
}
