export async function onRequestGet(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });

    try {
        const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

        // 1. Check of we vandaag al gemeten hebben
        const existing = await context.env.MY_DB.prepare("SELECT date FROM daily_stats WHERE date = ?").bind(today).first();

        if (!existing) {
            // 2. Zo niet: Bereken de stats van NU
            
            // Totaal Assets
            const countAssets = await context.env.MY_DB.prepare("SELECT COUNT(*) as c FROM assets").first();
            
            // Totaal Subs
            const countSubs = await context.env.MY_DB.prepare("SELECT COUNT(*) as c FROM subscriptions").first();
            
            // CIS Gemiddelde (excl NICs)
            const avgCis = await context.env.MY_DB.prepare("SELECT AVG(cis_score) as c FROM assets WHERE type != 'Network Interface'").first();
            
            // Vulns (Totaal Critical & High uit assets cache)
            // Let op: Dit vereist dat je vuln_count goed bijhoudt, of we doen een join. 
            // Voor nu doen we een query op de vulnerabilities tabel:
            const countCrit = await context.env.MY_DB.prepare("SELECT COUNT(*) as c FROM vulnerabilities WHERE severity = 'Critical' AND status = 'Open'").first();
            const countHigh = await context.env.MY_DB.prepare("SELECT COUNT(*) as c FROM vulnerabilities WHERE severity = 'High' AND status = 'Open'").first();

            // Eigenaarschap % (Assets die NIET leeg zijn qua owner)
            // Omdat owner encrypted is, checken we op lengte of null
            // (In SQLite is length van NULL ook NULL, dus we checken gewoon NOT NULL en != '')
            const countOwned = await context.env.MY_DB.prepare("SELECT COUNT(*) as c FROM assets WHERE owner_contact IS NOT NULL AND owner_contact != ''").first();
            
            const ownershipPct = countAssets.c > 0 ? Math.round((countOwned.c / countAssets.c) * 100) : 0;

            // Opslaan in daily_stats
            await context.env.MY_DB.prepare(`
                INSERT INTO daily_stats (date, total_assets, total_subs, avg_cis, vuln_critical, vuln_high, ownership_percentage)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).bind(today, countAssets.c, countSubs.c, Math.round(avgCis.c || 0), countCrit.c, countHigh.c, ownershipPct).run();
        }

        // 3. Haal historie op (gesorteerd op datum)
        const { results } = await context.env.MY_DB.prepare("SELECT * FROM daily_stats ORDER BY date ASC").all();

        return Response.json(results);

    } catch (err) {
        return Response.json({ error: err.message }, { status: 500 });
    }
}