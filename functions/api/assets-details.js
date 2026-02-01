export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  
  const url = new URL(context.request.url);
  const assetId = url.searchParams.get('id');

  // Haal alles tegelijk op
  const vulns = await context.env.MY_DB.prepare("SELECT * FROM vulnerabilities WHERE asset_id = ?").bind(assetId).all();
  const cis = await context.env.MY_DB.prepare("SELECT * FROM cis_exceptions WHERE asset_id = ?").bind(assetId).all();
  const history = await context.env.MY_DB.prepare("SELECT * FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC").bind(assetId).all();

  return Response.json({
      vulnerabilities: vulns.results,
      cis: cis.results,
      history: history.results
  });
}

export async function onRequestPost(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const data = await context.request.json();

  if (data.type === 'vuln') {
      await context.env.MY_DB.prepare(
          "INSERT INTO vulnerabilities (asset_id, name, severity, status, due_date) VALUES (?, ?, ?, ?, ?)"
      ).bind(data.asset_id, data.name, data.severity, data.status, data.due_date).run();
  } 
  else if (data.type === 'cis') {
      await context.env.MY_DB.prepare(
          "INSERT INTO cis_exceptions (asset_id, control_id, description, justification) VALUES (?, ?, ?, ?)"
      ).bind(data.asset_id, data.control_id, data.description, data.justification).run();
  }

  return new Response('Added', { status: 201 });
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const data = await context.request.json();
    
    if (data.type === 'vuln') {
        await context.env.MY_DB.prepare("DELETE FROM vulnerabilities WHERE id = ?").bind(data.id).run();
    } else if (data.type === 'cis') {
        await context.env.MY_DB.prepare("DELETE FROM cis_exceptions WHERE id = ?").bind(data.id).run();
    }
    
    return new Response('Deleted');
}