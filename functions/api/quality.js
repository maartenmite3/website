export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  
  try {
      // 1. ZOMBIES (STALE DATA) - Ouder dan 180 dagen (6 maanden)
      const sixMonthsAgo = Date.now() - (180 * 24 * 60 * 60 * 1000);
      
      // We kijken naar de laatste entry in history. Als er geen history is, kijken we naar created_at.
      const staleQuery = `
        SELECT a.id, a.name, a.type, MAX(h.timestamp) as last_seen 
        FROM assets a 
        LEFT JOIN asset_history h ON a.id = h.asset_id 
        GROUP BY a.id 
        HAVING (last_seen < ? OR (last_seen IS NULL AND a.created_at < ?))
      `;
      const { results: stale } = await context.env.MY_DB.prepare(staleQuery).bind(sixMonthsAgo, sixMonthsAgo).all();

      // 2. ORPHANS (WEES-ASSETS) - Geen relaties
      const orphanQuery = `
        SELECT a.id, a.name, a.type 
        FROM assets a 
        WHERE a.id NOT IN (SELECT parent_id FROM asset_relationships) 
        AND a.id NOT IN (SELECT child_id FROM asset_relationships)
        AND a.type != 'Network Interface' 
      `; 
      // N.B. NICs sluiten we vaak uit omdat die impliciet bij een VM horen
      const { results: orphans } = await context.env.MY_DB.prepare(orphanQuery).all();

      // 3. INCOMPLETE (MISSENDE DATA)
      // Check op lege Eigenaar, Subscriptie of Classificatie
      // We checken op NULL of lege strings (afhankelijk van encryptie resultaat)
      const allAssets = await context.env.MY_DB.prepare("SELECT id, name, type, owner_contact, subscription_id, classification FROM assets").all();
      const incomplete = [];
      
      for(const a of allAssets.results) {
          const missingFields = [];
          if (!a.owner_contact || a.owner_contact.length < 5) missingFields.push('owner');
          if (!a.subscription_id || a.subscription_id.length < 5) missingFields.push('subscription');
          if (!a.classification) missingFields.push('classification');
          
          if(missingFields.length > 0) {
              incomplete.push({ ...a, missing: missingFields });
          }
      }

      // 4. GHOST IPS (DUPLICATE IP's)
      // We gebruiken de hash om snel te groeperen
      const dupeIpQuery = `
        SELECT ip_hash, COUNT(*) as count 
        FROM asset_ips 
        WHERE ip_hash IS NOT NULL AND ip_hash != ''
        GROUP BY ip_hash 
        HAVING count > 1
      `;
      const { results: dupeHashes } = await context.env.MY_DB.prepare(dupeIpQuery).all();
      
      let duplicates = [];
      if(dupeHashes.length > 0) {
          // Haal de assets op die bij deze hashes horen
          const hashes = dupeHashes.map(d => d.ip_hash);
          // Let op: D1 heeft soms moeite met 'IN (?,?,?)', dus we doen een simpele loop of een join als alternatief.
          // Voor nu: simpele loop (veiligst bij kleine datasets) of raw query construction.
          // Oplossing: Haal gewoon alle IPs op en filter in JS (sneller bij <10k records).
          const allIps = await context.env.MY_DB.prepare("SELECT i.ip_address, a.id, a.name FROM asset_ips i JOIN assets a ON i.asset_id = a.id").all();
          
          // Groepeer in JS
          const ipGroups = {}; // hash -> [assets]
          // Hier zouden we decryptie moeten doen om het leesbare IP te tonen, 
          // maar voor de detectie gebruiken we de encrypted string als key.
          
          // Eenvoudigere aanpak voor display:
          // We sturen gewoon de lijst assets terug die "verdacht" zijn.
          // Hier laten we de frontend het zware werk doen of we sturen de raw list.
          duplicates = dupeHashes.map(h => ({ hash: h.ip_hash, count: h.count }));
      }

      return Response.json({
          stale,
          orphans,
          incomplete,
          duplicates
      });

  } catch (err) {
      return Response.json({ error: err.message }, { status: 500 });
  }
}