import bcrypt from 'bcryptjs';

// Hulpfunctie: Check of iemand admin is
function requireAdmin(context) {
  if (!context.data.user || context.data.user.role !== 'admin') {
    throw new Error('Unauthorized');
  }
}

// GET: Lijst van alle gebruikers ophalen
export async function onRequestGet(context) {
  try {
    requireAdmin(context); // Beveiliging!
    
    // Haal id, username en role op (GEEN wachtwoorden!)
    const { results } = await context.env.MY_DB.prepare(
      "SELECT id, username, role, mfa_enabled FROM users ORDER BY id DESC"
    ).all();

    return Response.json(results);
  } catch (err) {
    return new Response('Geen toegang', { status: 403 });
  }
}

// POST: Nieuwe gebruiker aanmaken
export async function onRequestPost(context) {
  try {
    requireAdmin(context);

    const { username, password, role } = await context.request.json();
    
    if (!username || !password) return new Response('Vul alles in', { status: 400 });

    // Hash het wachtwoord direct!
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Gebruik de opgegeven rol, of standaard 'user'
    const userRole = (role === 'admin') ? 'admin' : 'user';

    await context.env.MY_DB.prepare(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
    ).bind(username, hashedPassword, userRole).run();

    return new Response('Gebruiker aangemaakt', { status: 201 });
  } catch (err) {
    // Vang unieke constraint fout op (als naam al bestaat)
    if(err.message.includes('UNIQUE')) return new Response('Gebruikersnaam bestaat al', { status: 409 });
    return new Response(err.message, { status: 500 });
  }
}

// DELETE: Gebruiker verwijderen
export async function onRequestDelete(context) {
  try {
    requireAdmin(context);

    const { id } = await context.request.json();
    
    // Voorkom dat je jezelf verwijdert!
    if (id === context.data.user.id) {
      return new Response('Je kunt jezelf niet verwijderen', { status: 400 });
    }

    await context.env.MY_DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
    // Verwijder ook actieve sessies van die gebruiker
    await context.env.MY_DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();

    return new Response('Verwijderd', { status: 200 });
  } catch (err) {
    return new Response('Fout', { status: 500 });
  }
}