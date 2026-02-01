import bcrypt from 'bcryptjs';

// --- BEVEILIGING CHECK ---
function requireAdmin(context) {
  if (!context.data.user || context.data.user.role !== 'admin') {
    throw new Error('Unauthorized');
  }
}

// --- GET: LIJST OPHALEN ---
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

// --- POST: NIEUWE GEBRUIKER ---
export async function onRequestPost(context) {
  try {
    requireAdmin(context);

    const { username, password, role } = await context.request.json();
    
    if (!username || !password) return new Response('Vul alles in', { status: 400 });

    // Hash wachtwoord
    const hashedPassword = await bcrypt.hash(password, 10);
    const userRole = (role === 'admin') ? 'admin' : 'user';

    // Opslaan in DB
    await context.env.MY_DB.prepare(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
    ).bind(username, hashedPassword, userRole).run();

    // LOG DE ACTIE
    await logAction(context, 'CREATE_USER', `Gebruiker '${username}' (${userRole}) aangemaakt.`);

    return new Response('Gebruiker aangemaakt', { status: 201 });
  } catch (err) {
    if(err.message.includes('UNIQUE')) return new Response('Gebruikersnaam bestaat al', { status: 409 });
    return new Response(err.message, { status: 500 });
  }
}

// --- DELETE: VERWIJDEREN ---
export async function onRequestDelete(context) {
  try {
    requireAdmin(context);

    const { id } = await context.request.json();
    
    if (id === context.data.user.id) {
      return new Response('Je kunt jezelf niet verwijderen', { status: 400 });
    }

    // Haal naam op voor in de log voordat we verwijderen
    const targetUser = await context.env.MY_DB.prepare("SELECT username FROM users WHERE id = ?").bind(id).first();

    // Verwijder user en sessies
    await context.env.MY_DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();

    // LOG DE ACTIE
    if(targetUser) {
        await logAction(context, 'DELETE_USER', `Gebruiker '${targetUser.username}' (ID: ${id}) verwijderd.`);
    }

    return new Response('Verwijderd', { status: 200 });
  } catch (err) {
    return new Response('Fout', { status: 500 });
  }
}

// --- HULPFUNCTIE VOOR LOGGING ---
async function logAction(context, action, details) {
    const admin = context.data.user; // De admin die de actie uitvoert
    await context.env.MY_DB.prepare(
        "INSERT INTO logs (user_id, username, action, details, created_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(admin.id, admin.username, action, details, Date.now()).run();
}