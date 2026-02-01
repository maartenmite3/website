export async function onRequestGet(context) {
  // Omdat de middleware al gedraaid heeft, weten we wie de user is via context.data.user!
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  
  // Stuur veilige data terug (niet het wachtwoord!)
  return Response.json({ 
    username: context.data.user.username,
    mfa_enabled: context.data.user.mfa_enabled 
  });
}

export async function onRequestPut(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const { new_password } = await context.request.json();

  if (new_password) {
    await context.env.MY_DB.prepare('UPDATE users SET password = ? WHERE id = ?')
      .bind(new_password, context.data.user.id)
      .run();
  }
  
  return new Response('Updated');
}
