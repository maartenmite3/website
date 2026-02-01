// TIJDELIJKE TESTVERSIE: ZONDER ENCRYPTIE
// Hiermee testen we of de opslag functionaliteit werkt.

export async function onRequestGet(context) {
  // Check Auth
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });

  try {
    // Haal alles op
    const { results } = await context.env.MY_DB.prepare("SELECT * FROM assets ORDER BY created_at DESC").all();

    // Stuur direct terug (geen decryptie nodig in deze test)
    return Response.json(results);
  } catch (err) {
    return new Response('Database Fout: ' + err.message, { status: 500 });
  }
}

export async function onRequestPost(context) {
  // Check Auth
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });

  try {
    const { name, type, subscription_id, ip_address, cis_score, classification, data_sensitivity, owner_contact } = await context.request.json();

    if (!name) return new Response('Naam is verplicht', { status: 400 });

    // GEEN ENCRYPTIE: We slaan de tekst direct op
    await context.env.MY_DB.prepare(`
        INSERT INTO assets (name, type, subscription_id, ip_address, cis_score, classification, data_sensitivity, owner_contact, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(name, type, subscription_id, ip_address, cis_score, classification, data_sensitivity, owner_contact, Date.now()).run();

    return new Response('Asset toegevoegd', { status: 201 });
  } catch (err) {
    return new Response('Server Fout: ' + err.message, { status: 500 });
  }
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    try {
        const { id } = await context.request.json();
        await context.env.MY_DB.prepare("DELETE FROM assets WHERE id = ?").bind(id).run();
        return new Response('Verwijderd');
    } catch (err) {
        return new Response('Delete Fout: ' + err.message, { status: 500 });
    }
}