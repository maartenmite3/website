export async function onRequestGet(context) {
    const url = new URL(context.request.url);
    const id = url.searchParams.get('id');
    const type = url.searchParams.get('type');

    if (type === 'list') {
        const { results } = await context.env.MY_DB.prepare("SELECT id, name FROM assets ORDER BY name ASC").all();
        return Response.json(results);
    }

    if (!id) return new Response('Missing ID', { status: 400 });

    // Haal basis asset data
    const asset = await context.env.MY_DB.prepare("SELECT * FROM assets WHERE id = ?").bind(id).first();
    if (!asset) return new Response('Not found', { status: 404 });

    // Haal Risk Data (NIEUW)
    const risk = await context.env.MY_DB.prepare("SELECT * FROM asset_risks WHERE asset_id = ?").bind(id).first();

    // Haal sub-data (Vulns, CIS, History, Relaties)
    const vulns = await context.env.MY_DB.prepare("SELECT * FROM vulnerabilities WHERE asset_id = ?").bind(id).all();
    const cis = await context.env.MY_DB.prepare("SELECT * FROM cis_exceptions WHERE asset_id = ?").bind(id).all();
    const history = await context.env.MY_DB.prepare("SELECT * FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC LIMIT 20").bind(id).all();
    
    const relDown = await context.env.MY_DB.prepare(`
        SELECT r.id, r.relation_type, a.name, a.type, a.subscription_id as enc_sub_id, r.child_id as linked_asset_id 
        FROM asset_relationships r JOIN assets a ON r.child_id = a.id WHERE r.parent_id = ?
    `).bind(id).all();
    
    const relUp = await context.env.MY_DB.prepare(`
        SELECT r.id, r.relation_type, a.name, a.type, a.subscription_id as enc_sub_id, r.parent_id as linked_asset_id 
        FROM asset_relationships r JOIN assets a ON r.parent_id = a.id WHERE r.child_id = ?
    `).bind(id).all();

    const layout = await context.env.MY_DB.prepare("SELECT positions FROM network_layouts WHERE asset_id = ?").bind(id).first();

    return Response.json({
        asset,
        risk: risk || { impact: 0, likelihood: 0, justification: '' }, // Standaard leeg object
        vulnerabilities: vulns.results,
        cis: cis.results,
        history: history.results,
        relationships: { downstream: relDown.results, upstream: relUp.results },
        layout: layout ? JSON.parse(layout.positions) : null
    });
}

export async function onRequestPost(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const data = await context.request.json();
    
    // --- NIEUW: RISK SAVE ---
    if (data.type === 'risk') {
        const { asset_id, impact, likelihood, justification } = data;
        
        // Upsert (Insert of Update als bestaat)
        await context.env.MY_DB.prepare(`
            INSERT INTO asset_risks (asset_id, impact, likelihood, justification, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(asset_id) DO UPDATE SET
            impact=excluded.impact,
            likelihood=excluded.likelihood,
            justification=excluded.justification,
            updated_at=excluded.updated_at
        `).bind(asset_id, impact, likelihood, justification, Date.now()).run();

        // Log history
        await logHistory(context, asset_id, 'RISK_UPDATE', 'Risk Matrix Updated');
        return new Response('Risk Saved');
    }

    // Bestaande logica voor relaties, vulns, cis...
    if (data.type === 'rel') {
        await context.env.MY_DB.prepare("INSERT INTO asset_relationships (parent_id, child_id, relation_type) VALUES (?, ?, ?)").bind(data.parent_id, data.child_id, data.relation_type).run();
        await logHistory(context, data.parent_id, 'LINK', `Linked to ${data.child_id}`);
    } 
    else if (data.type === 'layout') {
        await context.env.MY_DB.prepare("INSERT INTO network_layouts (asset_id, positions) VALUES (?, ?) ON CONFLICT(asset_id) DO UPDATE SET positions=excluded.positions").bind(data.asset_id, JSON.stringify(data.positions)).run();
    }
    else if (data.type === 'vuln') {
        await context.env.MY_DB.prepare("INSERT INTO vulnerabilities (asset_id, name, severity, status, due_date) VALUES (?, ?, ?, ?, ?)").bind(data.asset_id, data.name, data.severity, data.status, data.due_date).run();
        // Update counter cache
        await updateVulnCount(context, data.asset_id);
    }
    else if (data.type === 'cis') {
        await context.env.MY_DB.prepare("INSERT INTO cis_exceptions (asset_id, control_id, description, justification) VALUES (?, ?, ?, ?)").bind(data.asset_id, data.control_id, data.description, data.justification).run();
    }

    return new Response('OK');
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const data = await context.request.json();
    
    if(data.type === 'rel') {
        await context.env.MY_DB.prepare("DELETE FROM asset_relationships WHERE id = ?").bind(data.id).run();
    } else if (data.type === 'vuln') {
        const assetId = await context.env.MY_DB.prepare("SELECT asset_id FROM vulnerabilities WHERE id = ?").bind(data.id).first();
        await context.env.MY_DB.prepare("DELETE FROM vulnerabilities WHERE id = ?").bind(data.id).run();
        if(assetId) await updateVulnCount(context, assetId.asset_id);
    } else if (data.type === 'cis') {
        await context.env.MY_DB.prepare("DELETE FROM cis_exceptions WHERE id = ?").bind(data.id).run();
    }
    return new Response('Deleted');
}

async function updateVulnCount(context, assetId) {
    const count = await context.env.MY_DB.prepare("SELECT COUNT(*) as c FROM vulnerabilities WHERE asset_id = ? AND severity IN ('Critical', 'High')").bind(assetId).first();
    await context.env.MY_DB.prepare("UPDATE assets SET vuln_count = ? WHERE id = ?").bind(count.c, assetId).run();
}

async function logHistory(context, assetId, type, details) {
    const user = context.data.user.username;
    await context.env.MY_DB.prepare("INSERT INTO asset_history (asset_id, changed_by, change_type, new_values, timestamp) VALUES (?, ?, ?, ?, ?)").bind(assetId, user, type, details, Date.now()).run();
}