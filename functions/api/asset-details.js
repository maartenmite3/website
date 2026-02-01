export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  
  const url = new URL(context.request.url);
  const assetId = url.searchParams.get('id');
  const type = url.searchParams.get('type');

  // 1. LIJST VOOR DROPDOWN
  if (type === 'list') {
      const { results } = await context.env.MY_DB.prepare("SELECT id, name FROM assets ORDER BY name ASC").all();
      return Response.json(results);
  }

  if (!assetId) return new Response('Missing ID', { status: 400 });

  try {
      const key = context.env.ENCRYPTION_KEY;

      // 2. DETAILS
      const vulns = await context.env.MY_DB.prepare("SELECT * FROM vulnerabilities WHERE asset_id = ?").bind(assetId).all();
      const cis = await context.env.MY_DB.prepare("SELECT * FROM cis_exceptions WHERE asset_id = ?").bind(assetId).all();
      const history = await context.env.MY_DB.prepare("SELECT * FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC").bind(assetId).all();
      
      // 3. LAYOUT POSITIES
      const layout = await context.env.MY_DB.prepare("SELECT positions FROM network_layouts WHERE asset_id = ?").bind(assetId).first();

      // 4. RELATIES OPHALEN (Met Subscriptie ID voor Threat Modeling!)
      // We moeten de subscription_id decrypten in JS, dus we halen hem encrypted op uit DB
      
      // Downstream
      const childrenQuery = await context.env.MY_DB.prepare(`
        SELECT r.id, r.relation_type, a.name, a.id as linked_asset_id, a.subscription_id as enc_sub_id, a.type
        FROM asset_relationships r 
        JOIN assets a ON r.child_id = a.id 
        WHERE r.parent_id = ?
      `).bind(assetId).all();

      // Upstream
      const parentsQuery = await context.env.MY_DB.prepare(`
        SELECT r.id, r.relation_type, a.name, a.id as linked_asset_id, a.subscription_id as enc_sub_id, a.type
        FROM asset_relationships r 
        JOIN assets a ON r.parent_id = a.id 
        WHERE r.child_id = ?
      `).bind(assetId).all();

      // Helper decrypt functie binnen scope
      const decrypt = (txt) => {
          if(!txt || !txt.includes(':')) return txt;
          try {
            // ... (Hier herbruiken we node logic niet direct makkelijk zonder import, 
            // maar voor simple display sturen we de raw encrypted tekst of we doen de decryptie in assets.js logic. 
            // ECHTER: Om Zero Trust te checken hebben we de tekst nodig.
            // Oplossing: We doen de check in de Frontend op basis van gelijkheid van strings (encrypted A == encrypted A),
            // OF we decrypten hier als we de import hebben.
            // Laten we ervan uitgaan dat de strings uniek zijn, dus vergelijken werkt ook versleuteld.)
            return txt; 
          } catch(e) { return txt; }
      };

      return Response.json({
          vulnerabilities: vulns.results || [],
          cis: cis.results || [],
          history: history.results || [],
          layout: layout ? JSON.parse(layout.positions) : null,
          relationships: {
              downstream: childrenQuery.results || [],
              upstream: parentsQuery.results || []
          }
      });
  } catch (err) {
      return new Response('Server Error: ' + err.message, { status: 500 });
  }
}

export async function onRequestPost(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const data = await context.request.json();

  if (data.type === 'vuln') {
      await context.env.MY_DB.prepare("INSERT INTO vulnerabilities (asset_id, name, severity, status, due_date) VALUES (?, ?, ?, ?, ?)").bind(data.asset_id, data.name, data.severity, data.status, data.due_date).run();
  } 
  else if (data.type === 'cis') {
      await context.env.MY_DB.prepare("INSERT INTO cis_exceptions (asset_id, control_id, description, justification) VALUES (?, ?, ?, ?)").bind(data.asset_id, data.control_id, data.description, data.justification).run();
  }
  else if (data.type === 'rel') {
      const exists = await context.env.MY_DB.prepare("SELECT id FROM asset_relationships WHERE parent_id=? AND child_id=?").bind(data.parent_id, data.child_id).first();
      if(!exists) {
          await context.env.MY_DB.prepare("INSERT INTO asset_relationships (parent_id, child_id, relation_type) VALUES (?, ?, ?)").bind(data.parent_id, data.child_id, data.relation_type).run();
      }
  }
  else if (data.type === 'layout') {
      // NIEUW: Layout Opslaan
      // Upsert (Insert or Replace)
      await context.env.MY_DB.prepare("INSERT OR REPLACE INTO network_layouts (asset_id, positions) VALUES (?, ?)").bind(data.asset_id, JSON.stringify(data.positions)).run();
  }

  return new Response('Added', { status: 201 });
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const data = await context.request.json();
    
    if (data.type === 'vuln') await context.env.MY_DB.prepare("DELETE FROM vulnerabilities WHERE id = ?").bind(data.id).run();
    else if (data.type === 'cis') await context.env.MY_DB.prepare("DELETE FROM cis_exceptions WHERE id = ?").bind(data.id).run();
    else if (data.type === 'rel') await context.env.MY_DB.prepare("DELETE FROM asset_relationships WHERE id = ?").bind(data.id).run();
    
    return new Response('Deleted');
}