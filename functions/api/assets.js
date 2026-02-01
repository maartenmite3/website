import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

// --- HELPERS ---
function encrypt(text, keyString) {
  if (!text) return null;
  const key = Buffer.alloc(32); key.write(keyString || '');
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText, keyString) {
  if (!encryptedText || !encryptedText.includes(':')) return encryptedText;
  try {
      const key = Buffer.alloc(32); key.write(keyString || '');
      const textParts = encryptedText.split(':');
      const iv = Buffer.from(textParts.shift(), 'hex');
      const encryptedData = textParts.join(':');
      const decipher = createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
  } catch (e) { return "[Fout]"; }
}

function hashIP(ip) {
    if (!ip) return null;
    return createHash('sha256').update(ip.trim()).digest('hex');
}

// --- API ---

export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const key = context.env.ENCRYPTION_KEY;

  // History request?
  const url = new URL(context.request.url);
  const historyId = url.searchParams.get('history');
  if (historyId) {
      const { results } = await context.env.MY_DB.prepare("SELECT * FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC").bind(historyId).all();
      return Response.json(results);
  }

  // 1. Haal assets op
  const assetsQuery = await context.env.MY_DB.prepare("SELECT * FROM assets ORDER BY created_at DESC").all();
  const assets = assetsQuery.results;

  // 2. Haal alle IPs op
  const ipsQuery = await context.env.MY_DB.prepare("SELECT * FROM asset_ips").all();
  const ipMap = {};
  
  // Groepeer IPs per asset
  ipsQuery.results.forEach(row => {
      if(!ipMap[row.asset_id]) ipMap[row.asset_id] = [];
      ipMap[row.asset_id].push(decrypt(row.ip_address, key));
  });

  // 3. Combineer en decrypt
  const decryptedResults = assets.map(asset => {
      // Als er nog geen IPs in de subtabel staan (oude data), gebruik dan de kolom uit de hoofdtabel
      let assetIps = ipMap[asset.id] || [];
      const mainIp = decrypt(asset.ip_address, key);
      
      // Fallback: als asset_ips leeg is, maar hoofdtabel niet, voeg die toe aan de lijst
      if(assetIps.length === 0 && mainIp) assetIps = [mainIp];

      return {
          ...asset,
          subscription_id: decrypt(asset.subscription_id, key),
          ip_address: mainIp, // Blijft primary voor display
          ips: assetIps,      // De volledige lijst
          owner_contact: decrypt(asset.owner_contact, key)
      };
  });

  return Response.json(decryptedResults);
}

export async function onRequestPost(context) {
  return handleSave(context, 'POST');
}

export async function onRequestPut(context) {
  return handleSave(context, 'PUT');
}

async function handleSave(context, method) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const key = context.env.ENCRYPTION_KEY;
  const data = await context.request.json();
  const id = data.id;

  // 1. Validatie: Splits IPs
  // We verwachten "1.1.1.1, 2.2.2.2"
  const rawIps = data.ip_address ? data.ip_address.split(',').map(s => s.trim()).filter(s => s) : [];
  if (rawIps.length === 0) rawIps.push(''); // Lege entry toestaan als placeholder? Of error? Laten we leeg toestaan.

  // 2. Check Uniekheid (Naam & IPs)
  // Check Naam
  let query = "SELECT id FROM assets WHERE name = ?";
  let params = [data.name];
  if (method === 'PUT') { query += " AND id != ?"; params.push(id); }
  
  const existingName = await context.env.MY_DB.prepare(query).bind(...params).first();
  if (existingName) return new Response('Naam bestaat al.', { status: 409 });

  // Check IPs (Loop door alle opgegeven IPs)
  for (const ip of rawIps) {
      if(!ip) continue;
      const h = hashIP(ip);
      // Check in hoofdtabel (legacy) en subtabel
      // Let op: Bij PUT mag het IP wel bestaan als het bij DEZE asset hoort.
      
      // Check hoofdtabel (ip_hash column)
      let q1 = "SELECT id FROM assets WHERE ip_hash = ?";
      let p1 = [h];
      if (method === 'PUT') { q1 += " AND id != ?"; p1.push(id); }
      const conflict1 = await context.env.MY_DB.prepare(q1).bind(...p1).first();
      if (conflict1) return new Response(`IP ${ip} is al in gebruik (hoofdtabel).`, { status: 409 });

      // Check subtabel
      let q2 = "SELECT asset_id FROM asset_ips WHERE ip_hash = ?";
      let p2 = [h];
      if (method === 'PUT') { q2 += " AND asset_id != ?"; p2.push(id); }
      const conflict2 = await context.env.MY_DB.prepare(q2).bind(...p2).first();
      if (conflict2) return new Response(`IP ${ip} is al in gebruik.`, { status: 409 });
  }

  // 3. Voorbereiden data
  const primaryIp = rawIps[0] || ''; // Eerste is 'hoofd' IP
  const primaryHash = hashIP(primaryIp);
  const encPrimaryIp = encrypt(primaryIp, key);
  
  const encSub = encrypt(data.subscription_id, key);
  const encOwner = encrypt(data.owner_contact, key);
  const sensitivity = Array.isArray(data.data_sensitivity) ? data.data_sensitivity.join(', ') : data.data_sensitivity;

  let assetId = id;

  if (method === 'POST') {
      const res = await context.env.MY_DB.prepare(`
        INSERT INTO assets (name, type, subscription_id, ip_address, ip_hash, cis_score, classification, data_sensitivity, owner_contact, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
      `).bind(data.name, data.type, encSub, encPrimaryIp, primaryHash, data.cis_score, data.classification, sensitivity, encOwner, Date.now()).first();
      assetId = res.id;
      await logHistory(context, assetId, 'CREATE', null, JSON.stringify(data));
  } else {
      // Haal oude data op voor history
      const oldAsset = await context.env.MY_DB.prepare("SELECT * FROM assets WHERE id = ?").bind(id).first();
      const readableOld = { ...oldAsset, ip_address: decrypt(oldAsset.ip_address, key) }; // Simpele versie
      
      await context.env.MY_DB.prepare(`
        UPDATE assets SET name=?, type=?, subscription_id=?, ip_address=?, ip_hash=?, cis_score=?, classification=?, data_sensitivity=?, owner_contact=?
        WHERE id=?
      `).bind(data.name, data.type, encSub, encPrimaryIp, primaryHash, data.cis_score, data.classification, sensitivity, encOwner, id).run();
      
      await logHistory(context, id, 'UPDATE', JSON.stringify(readableOld), JSON.stringify(data));
      
      // Verwijder oude IPs uit subtabel om schoon te beginnen (simpelste update strategie)
      await context.env.MY_DB.prepare("DELETE FROM asset_ips WHERE asset_id = ?").bind(id).run();
  }

  // 4. Sla alle IPs op in asset_ips
  if (rawIps.length > 0) {
      const stmt = context.env.MY_DB.prepare("INSERT INTO asset_ips (asset_id, ip_address, ip_hash) VALUES (?, ?, ?)");
      const batch = [];
      for (const ip of rawIps) {
          if(!ip) continue;
          batch.push(stmt.bind(assetId, encrypt(ip, key), hashIP(ip)));
      }
      if(batch.length > 0) await context.env.MY_DB.batch(batch);
  }

  return new Response(method === 'POST' ? 'Created' : 'Updated', { status: method === 'POST' ? 201 : 200 });
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const { id } = await context.request.json();
    await context.env.MY_DB.prepare("DELETE FROM assets WHERE id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM asset_ips WHERE asset_id = ?").bind(id).run(); // Ook IPs weg
    await context.env.MY_DB.prepare("DELETE FROM asset_history WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM vulnerabilities WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM cis_exceptions WHERE asset_id = ?").bind(id).run();
    return new Response('Verwijderd');
}

async function logHistory(context, assetId, type, oldVal, newVal) {
    const user = context.data.user.username;
    await context.env.MY_DB.prepare(
        "INSERT INTO asset_history (asset_id, changed_by, change_type, old_values, new_values, timestamp) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(assetId, user, type, oldVal, newVal, Date.now()).run();
}