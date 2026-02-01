export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  
  const url = new URL(context.request.url);
  const limit = 50;
  const page = parseInt(url.searchParams.get('page') || '1');
  const offset = (page - 1) * limit;

  // Haal logs op + de huidige naam van de asset (als die nog bestaat)
  // We gebruiken een LEFT JOIN omdat assets verwijderd kunnen zijn
  const query = `
    SELECT h.*, a.name as current_name 
    FROM asset_history h 
    LEFT JOIN assets a ON h.asset_id = a.id 
    ORDER BY h.timestamp DESC 
    LIMIT ? OFFSET ?
  `;
  
  const { results } = await context.env.MY_DB.prepare(query).bind(limit, offset).all();
  
  // Totaal aantal tellen voor paginering
  const count = await context.env.MY_DB.prepare("SELECT COUNT(*) as total FROM asset_history").first();

  return Response.json({
      data: results,
      meta: { total: count.total, page: page, pages: Math.ceil(count.total / limit) }
  });
}

export async function onRequestPost(context) {
    // RESTORE FUNCTIONALITEIT
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const data = await context.request.json();

    if (data.action === 'restore') {
        const historyId = data.id;
        
        // 1. Haal de oude waardes op uit de geschiedenis
        const record = await context.env.MY_DB.prepare("SELECT * FROM asset_history WHERE id = ?").bind(historyId).first();
        if (!record || !record.old_values) return new Response('Geen hersteldata gevonden', { status: 404 });

        const oldData = JSON.parse(record.old_values);
        const assetId = record.asset_id;

        // 2. Check of asset nog bestaat
        const exists = await context.env.MY_DB.prepare("SELECT id FROM assets WHERE id = ?").bind(assetId).first();
        if (!exists) return new Response('Asset bestaat niet meer (is verwijderd). Kan niet herstellen.', { status: 400 });

        // 3. Update de asset terug naar de oude waardes
        // Let op: We herstellen alleen de hoofdvelden, niet de relaties/IPs in subtabellen voor nu (complexiteit)
        await context.env.MY_DB.prepare(`
            UPDATE assets 
            SET name=?, type=?, subscription_id=?, cis_score=?, classification=?, data_sensitivity=?, owner_contact=?
            WHERE id=?
        `).bind(
            oldData.name, oldData.type, oldData.subscription_id, 
            oldData.cis_score, oldData.classification, oldData.data_sensitivity, oldData.owner_contact, 
            assetId
        ).run();

        // 4. Log deze herstelactie ook weer!
        const user = context.data.user.username;
        await context.env.MY_DB.prepare("INSERT INTO asset_history (asset_id, changed_by, change_type, old_values, new_values, timestamp) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(assetId, user, 'RESTORE', record.new_values, record.old_values, Date.now()).run();

        return new Response('Hersteld', { status: 200 });
    }

    return new Response('Invalid Action', { status: 400 });
}