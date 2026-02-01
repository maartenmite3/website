// GET: Haal user info op (voor het dashboard)
export async function onRequestGet(context) {
  if (!context.data.user) {
    return new Response('Niet ingelogd', { status: 401 });
  }
  
  return Response.json({ 
    username: context.data.user.username,
    mfa_enabled: context.data.user.mfa_enabled 
  });
}

// PUT: Update wachtwoord
export async function onRequestPut(context) {
  try {
    // 1. Check of gebruiker is ingelogd (via middleware)
    if (!context.data.user) {
      return new Response('Niet geautoriseerd', { status: 401 });
    }

    // 2. Lees de JSON data
    const data = await context.request.json();
    const newPassword = data.new_password;

    if (!newPassword) {
      return new Response('Geen wachtwoord opgegeven', { status: 400 });
    }

    // 3. Update de database
    // We gebruiken .run() omdat we geen resultaten terugkrijgen, alleen een bevestiging
    const info = await context.env.MY_DB.prepare('UPDATE users SET password = ? WHERE id = ?')
      .bind(newPassword, context.data.user.id)
      .run();

    // 4. Check of de update gelukt is
    if (info.success) {
      return new Response('Updated', { status: 200 });
    } else {
      return new Response('Database fout', { status: 500 });
    }

  } catch (err) {
    // Vang onverwachte fouten op en stuur ze terug zodat je ze in de browser console ziet
    return new Response(err.message, { status: 500 });
  }
}
