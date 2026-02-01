import bcrypt from 'bcryptjs';

// GET: User Info
export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Niet ingelogd', { status: 401 });
  return Response.json({ 
    username: context.data.user.username,
    mfa_enabled: context.data.user.mfa_enabled 
  });
}

// PUT: Update Wachtwoord (VEILIG)
export async function onRequestPut(context) {
  try {
    if (!context.data.user) return new Response('Niet geautoriseerd', { status: 401 });

    const { new_password } = await context.request.json();
    if (!new_password) return new Response('Leeg wachtwoord', { status: 400 });

    // HIER GEBEURT DE MAGIE: We hashen het wachtwoord
    // 10 is de "cost factor" (hoeveel rondes rekenwerk)
    const hashedPassword = await bcrypt.hash(new_password, 10);

    await context.env.MY_DB.prepare('UPDATE users SET password = ? WHERE id = ?')
      .bind(hashedPassword, context.data.user.id)
      .run();

    return new Response('Updated', { status: 200 });

  } catch (err) {
    return new Response(err.message, { status: 500 });
  }
}