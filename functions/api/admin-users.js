import bcrypt from 'bcryptjs';

// Hulpfunctie
function requireAdmin(context) {
  if (!context.data.user || context.data.user.role !== 'admin') {
    throw new Error('Unauthorized');
  }
}

// 1. GET: Lijst ophalen (deze werkt waarschijnlijk wel, want je tabel laadt)
export async function onRequestGet(context) {
  try {
    requireAdmin(context);
    const { results } = await context.env.MY_DB.prepare(
      "SELECT id, username, role, mfa_enabled FROM users ORDER BY id DESC"
    ).all();
    return Response.json(results);
  } catch (err) {
    return new Response('Geen toegang', { status: 403 });
  }
}

// 2. POST: Nieuwe gebruiker (DEZE VEROORZAAKT DE 405 FOUT ALS HIJ ONTBREEKT)
export async function onRequestPost(context) {
  try {
    requireAdmin(context);

    const { username, password, role } = await context.request.json();
    if (!username || !password) return new Response('Vul alles in', { status: 400 });

    const hashedPassword = await bcrypt.hash(password, 10);
    const userRole = (role === 'admin') ? 'admin' : 'user';

    await context.env.MY_DB.prepare(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
    ).bind(username, hashedPassword, userRole).run();

    return new Response('Gebruiker aangemaakt', { status: 201 });
  } catch (err) {
    if(err.message.includes('UNIQUE')) return new Response('Naam bestaat al', { status: 409 });
    return new Response(err.message, { status: 500 });
  }
}

// 3. DELETE: Verwijderen
export async function onRequestDelete(context) {
  try {
    requireAdmin(context);
    const { id } = await context.request.json();
    
    if (id === context.data.user.id) return new Response('Niet jezelf verwijderen', { status: 400 });

    await context.env.MY_DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();

    return new Response('Verwijderd', { status: 200 });
  } catch (err) {
    return new Response('Fout', { status: 500 });
  }
}