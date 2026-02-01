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

  const url = new URL(context.request.url);
  
  // 1. Check voor History request (blijft hetzelfde)
  const historyId = url.searchParams.get('history');
  if (historyId) {
      const { results } = await context.env.MY_DB.prepare("SELECT * FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC").bind(historyId).all();
      return Response.json(results);
  }

  // 2. Haal parameters op voor Filter & Limit
  const search = (url.searchParams.get('q') || '').toLowerCase();
  const limitParam = url.searchParams.get('limit') || '25';
  
  // 3. Haal ALLES op (Database is snel genoeg voor 800-2000 rows)
  // We moeten alles ophalen om te kunnen zoeken in versleutelde velden
  const assetsQuery = await context.env.MY_DB.prepare("SELECT * FROM assets ORDER BY created_at DESC").all();
  const assets = assetsQuery.results;

  // Haal IPs op
  const ipsQuery = await context.env.MY_DB.prepare("SELECT * FROM asset_ips").all();
  const ipMap = {};
  ipsQuery.results.forEach(row => {
      if(!ipMap[row.asset_id]) ipMap[row.asset_id] = [];
      ipMap[row.asset_id].push(decrypt(row.ip_address, key));
  });

  // 4. Decrypt, Filter en Slice in memory (Server Side = Snel)
  let processed = [];
  
  for (const asset of assets) {
      // Decrypt eerst de velden
      const assetIps = ipMap[asset.id] || [];
      const mainIp = decrypt(asset.ip_address, key);
      if(assetIps.length === 0 && mainIp) assetIps.push(mainIp);

      const subId = decrypt(asset.subscription_id, key);
      const owner = decrypt(asset.owner_contact, key);

      // Het object zoals het naar de frontend zou gaan
      const item = {
          ...asset,
          subscription_id: subId,
          ip_address: mainIp,
          ips: assetIps,
          owner_contact: owner
      };

      // FILTER LOGICA: Als er een zoekterm is, check dan of die voorkomt
      if (search) {
          const searchString = `${item.name} ${item.ip_address} ${assetIps.join(' ')} ${item.subscription_id} ${item.owner_contact}`.toLowerCase();
          if (!searchString.includes(search)) {
              continue; // Skip dit item, past niet bij zoekopdracht
          }
      }

      processed.push(item);
  }

  // 5. Apply Limit (Pagination)
  // Als limit 'all' is, stuur alles, anders knip de array af
  if (limitParam !== 'all') {
      const limit = parseInt(limitParam);
      processed = processed.slice(0, limit);
  }

  return Response.json(processed);
}

export async function onRequestPost(context) { return handleSave(context, 'POST'); }
export async function onRequestPut(context) { return handleSave(context, 'PUT'); }

async function handleSave(context, method) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const key = context.env.ENCRYPTION_KEY;
  const data = await context.request.json();
  const id = data.id;

  const rawIps = data.ip_address ? data.ip_address.split(',').map(s => s.trim()).filter(s => s) : [];
  if (rawIps.length === 0) rawIps.push('');

  // Check Uniekheid
  let query = "SELECT id FROM assets WHERE name = ?";
  let params = [data.name];
  if (method === 'PUT') { query += " AND id != ?"; params.push(id); }
  const existingName = await context.env.MY_DB.prepare(query).bind(...params).first();
  if (existingName) return new Response('Naam bestaat al.', { status: 409 });

  for (const ip of rawIps) {
      if(!ip) continue;
      const h = hashIP(ip);
      let q1 = "SELECT id FROM assets WHERE ip_hash = ?";
      let p1 = [h];
      if (method === 'PUT') { q1 += " AND id != ?"; p1.push(id); }
      const conflict1 = await context.env.MY_DB.prepare(q1).bind(...p1).first();
      if (conflict1) return new Response(`IP ${ip} is al in gebruik.`, { status: 409 });

      let q2 = "SELECT asset_id FROM asset_ips WHERE ip_hash = ?";
      let p2 = [h];
      if (method === 'PUT') { q2 += " AND asset_id != ?"; p2.push(id); }
      const conflict2 = await context.env.MY_DB.prepare(q2).bind(...p2).first();
      if (conflict2) return new Response(`IP ${ip} is al in gebruik.`, { status: 409 });
  }

  const primaryIp = rawIps[0] || '';
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
      const oldAsset = await context.env.MY_DB.prepare("SELECT * FROM assets WHERE id = ?").bind(id).first();
      const readableOld = { ...oldAsset, ip_address: decrypt(oldAsset.ip_address, key) };
      await context.env.MY_DB.prepare(`
        UPDATE assets SET name=?, type=?, subscription_id=?, ip_address=?, ip_hash=?, cis_score=?, classification=?, data_sensitivity=?, owner_contact=?
        WHERE id=?
      `).bind(data.name, data.type, encSub, encPrimaryIp, primaryHash, data.cis_score, data.classification, sensitivity, encOwner, id).run();
      await logHistory(context, id, 'UPDATE', JSON.stringify(readableOld), JSON.stringify(data));
      await context.env.MY_DB.prepare("DELETE FROM asset_ips WHERE asset_id = ?").bind(id).run();
  }

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
    await context.env.MY_DB.prepare("DELETE FROM asset_ips WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM asset_history WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM vulnerabilities WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM cis_exceptions WHERE asset_id = ?").bind(id).run();
    return new Response('Verwijderd');
}

async function logHistory(context, assetId, type, oldVal, newVal) {
    const user = context.data.user.username;
    await context.env.MY_DB.prepare("INSERT INTO asset_history (asset_id, changed_by, change_type, old_values, new_values, timestamp) VALUES (?, ?, ?, ?, ?, ?)").bind(assetId, user, type, oldVal, newVal, Date.now()).run();
}