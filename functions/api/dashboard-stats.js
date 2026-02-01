export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });

  try {
    // 1. Totaal aantal assets
    const totalQuery = await context.env.MY_DB.prepare("SELECT COUNT(*) as count FROM assets").first();
    
    // 2. Gemiddelde CIS Score (AANGEPAST)
    // We negeren assets met score 0 EN specifieke types zoals Network Interfaces
    const avgCisQuery = await context.env.MY_DB.prepare(`
        SELECT AVG(cis_score) as avg 
        FROM assets 
        WHERE cis_score > 0 
        AND type != 'Network Interface'
    `).first();

    // 3. Verdeling Classificatie
    const classQuery = await context.env.MY_DB.prepare("SELECT classification, COUNT(*) as count FROM assets GROUP BY classification").all();

    // 4. Aantal open kwetsbaarheden
    const vulnsQuery = await context.env.MY_DB.prepare("SELECT severity, COUNT(*) as count FROM vulnerabilities WHERE status != 'Opgelost' GROUP BY severity").all();

    return Response.json({
        total_assets: totalQuery.count,
        avg_cis: Math.round(avgCisQuery.avg || 0), // Rond af, of 0 als er geen data is
        classification_stats: classQuery.results,
        vuln_stats: vulnsQuery.results
    });

  } catch (err) {
    return new Response('Error: ' + err.message, { status: 500 });
  }
}