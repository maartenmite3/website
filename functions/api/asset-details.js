export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  
  const url = new URL(context.request.url);
  const assetId = url.searchParams.get('id');
  const type = url.searchParams.get('type'); // Nieuw: optie om 'lite' list op te halen

  // NIEUW: Helper om simpele lijst van alle assets op te halen (voor dropdown in relaties)
  if (type === 'list') {
      const { results } = await context.env.MY_DB.prepare("SELECT id, name FROM assets ORDER BY name ASC").all();
      return Response.json(results);
  }

  if (!assetId) return new Response('Missing ID', { status: 400 });

  try {
      // 1. Haal details op
      const vulns = await context.env.MY_DB.prepare("SELECT * FROM vulnerabilities WHERE asset_id = ?").bind(assetId).all();
      const cis = await context.env.MY_DB.prepare("SELECT * FROM cis_exceptions WHERE asset_id = ?").bind(assetId).all();
      const history = await context.env.MY_DB.prepare("SELECT * FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC").bind(assetId).all();

      // 2. Haal Relaties op (JOIN met assets tabel om de NAAM van de gekoppelde asset te zien)
      // We halen op waar deze asset de PARENT is
      const children = await context.env.MY_DB.prepare(`
        SELECT r.id, r.relation_type, a.name, a.id as linked_asset_id 
        FROM asset_relationships r 
        JOIN assets a ON r.child_id = a.id 
        WHERE r.parent_id = ?
      `).bind(assetId).all();

      // We halen op waar deze asset de CHILD is
      const parents = await context.env.MY_DB.prepare(`
        SELECT r.id, r.relation_type, a.name, a.id as linked_asset_id 
        FROM asset_relationships r 
        JOIN assets a ON r.parent_id = a.id 
        WHERE r.child_id = ?
      `).bind(assetId).all();

      return Response.json({
          vulnerabilities: vulns.results || [],
          cis: cis.results || [],
          history: history.results || [],
          relationships: {
              downstream: children.results || [], // Waar ik van afhang
              upstream: parents.results || []     // Wie van mij afhangt
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
      // NIEUW: Relatie toevoegen
      // Check of relatie al bestaat
      const exists = await context.env.MY_DB.prepare("SELECT id FROM asset_relationships WHERE parent_id=? AND child_id=?").bind(data.parent_id, data.child_id).first();
      if(!exists) {
          await context.env.MY_DB.prepare("INSERT INTO asset_relationships (parent_id, child_id, relation_type) VALUES (?, ?, ?)").bind(data.parent_id, data.child_id, data.relation_type).run();
      }
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