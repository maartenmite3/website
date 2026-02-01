import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

// --- HELPERS (Encryptie) ---
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

// --- API HANDLERS ---

export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const key = context.env.ENCRYPTION_KEY;
  const url = new URL(context.request.url);
  
  // Zoek parameters
  const search = (url.searchParams.get('q') || '').toLowerCase();
  const limitParam = url.searchParams.get('limit') || '25';
  const pageParam = parseInt(url.searchParams.get('page') || '1');
  
  // Haal Assets op (Nu inclusief os_type en os_version)
  const assetsQuery = await context.env.MY_DB.prepare("SELECT * FROM assets ORDER BY created_at DESC").all();
  const assets = assetsQuery.results;

  // Haal IPs op
  const ipsQuery = await context.env.MY_DB.prepare("SELECT * FROM asset_ips").all();
  const ipMap = {};
  ipsQuery.results.forEach(row => {
      if(!ipMap[row.asset_id]) ipMap[row.asset_id] = [];
      ipMap[row.asset_id].push(decrypt(row.ip_address, key));
  });

  // Decryptie en Processing
  let processed = [];
  for (const asset of assets) {
      const assetIps = ipMap[asset.id] || [];
      const mainIp = decrypt(asset.ip_address, key);
      if(assetIps.length === 0 && mainIp) assetIps.push(mainIp);

      const item = {
          ...asset,
          subscription_id: decrypt(asset.subscription_id, key),
          ip_address: mainIp,
          ips: assetIps,
          owner_contact: decrypt(asset.owner_contact, key)
      };

      if (search) {
          const searchString = `${item.name} ${item.ip_address} ${assetIps.join(' ')} ${item.subscription_id} ${item.owner_contact} ${item.os_type || ''}`.toLowerCase();
          if (!searchString.includes(search)) continue;
      }
      processed.push(item);
  }

  // Paginering
  const totalItems = processed.length;
  let pagedData = processed;
  let totalPages = 1;

  if (limitParam !== 'all') {
      const limit = parseInt(limitParam);
      totalPages = Math.ceil(totalItems / limit);
      const currentPage = Math.min(Math.max(1, pageParam), totalPages || 1);
      const startIndex = (currentPage - 1) * limit;
      pagedData = processed.slice(startIndex, startIndex + limit);
  }

  return Response.json({ data: pagedData, meta: { total: totalItems, page: pageParam, pages: totalPages } });
}

export async function onRequestPost(context) { 
    const data = await context.request.json();
    return handleSave(context, 'POST', data); 
}

export async function onRequestPut(context) { 
    const data = await context.request.json();
    // Bulk update detectie
    if (data.mode === 'bulk' && Array.isArray(data.ids)) {
        return handleBulkUpdate(context, data);
    }
    return handleSave(context, 'PUT', data); 
}

// --- BULK UPDATE ---
async function handleBulkUpdate(context, data) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const key = context.env.ENCRYPTION_KEY;
    const { ids, field, value } = data;

    // Whitelist toegestane velden
    const allowedFields = ['owner_contact', 'subscription_id', 'classification', 'type', 'cis_score', 'os_type', 'os_version'];
    if (!allowedFields.includes(field)) return new Response('Invalid field', { status: 400 });

    let finalValue = value;
    if (field === 'owner_contact' || field === 'subscription_id') {
        finalValue = encrypt(value, key);
    }

    const stmt = context.env.MY_DB.prepare(`UPDATE assets SET ${field} = ? WHERE id = ?`);
    const batch = [];
    for (const id of ids) { batch.push(stmt.bind(finalValue, id)); }
    
    // Chunking voor D1 limieten
    const chunkSize = 50;
    for (let i = 0; i < batch.length; i += chunkSize) {
        await context.env.MY_DB.batch(batch.slice(i, i + chunkSize));
    }
    
    return new Response('Bulk update success', { status: 200 });
}

// --- SAVE (CREATE / UPDATE) ---
async function handleSave(context, method, data) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const key = context.env.ENCRYPTION_KEY;
  const id = data.id;

  // IPs verwerken
  const rawIps = data.ip_address ? data.ip_address.split(',').map(s => s.trim()).filter(s => s) : [];
  if (rawIps.length === 0) rawIps.push('');

  // Uniekheid check (Naam)
  let query = "SELECT id FROM assets WHERE name = ?"; let params = [data.name];
  if (method === 'PUT') { query += " AND id != ?"; params.push(id); }
  const existingName = await context.env.MY_DB.prepare(query).bind(...params).first();
  if (existingName) return new Response('Naam bestaat al.', { status: 409 });

  // Encryptie
  const primaryIp = rawIps[0] || '';
  const primaryHash = hashIP(primaryIp);
  const encPrimaryIp = encrypt(primaryIp, key);
  const encSub = encrypt(data.subscription_id, key);
  const encOwner = encrypt(data.owner_contact, key);
  const sensitivity = Array.isArray(data.data_sensitivity) ? data.data_sensitivity.join(', ') : data.data_sensitivity;

  let assetId = id;

  if (method === 'POST') {
      // INSERT met os_type en os_version
      const res = await context.env.MY_DB.prepare(`
        INSERT INTO assets (name, type, subscription_id, ip_address, ip_hash, cis_score, classification, data_sensitivity, owner_contact, os_type, os_version, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
      `).bind(
          data.name, data.type, encSub, encPrimaryIp, primaryHash, data.cis_score, 
          data.classification, sensitivity, encOwner, 
          data.os_type, data.os_version, // <-- De nieuwe velden
          Date.now()
      ).first();
      assetId = res.id;
      
      await logHistory(context, assetId, 'CREATE', null, JSON.stringify(data));

  } else {
      // UPDATE met os_type en os_version
      const oldAsset = await context.env.MY_DB.prepare("SELECT * FROM assets WHERE id = ?").bind(id).first();
      const readableOld = { ...oldAsset, ip_address: decrypt(oldAsset.ip_address, key) };
      
      await context.env.MY_DB.prepare(`
        UPDATE assets SET 
            name=?, type=?, subscription_id=?, ip_address=?, ip_hash=?, 
            cis_score=?, classification=?, data_sensitivity=?, owner_contact=?, 
            os_type=?, os_version=? 
        WHERE id=?
      `).bind(
          data.name, data.type, encSub, encPrimaryIp, primaryHash, 
          data.cis_score, data.classification, sensitivity, encOwner, 
          data.os_type, data.os_version, // <-- De nieuwe velden
          id
      ).run();

      await logHistory(context, id, 'UPDATE', JSON.stringify(readableOld), JSON.stringify(data));
      
      // IPs verversen (eerst wissen, dan nieuw toevoegen)
      await context.env.MY_DB.prepare("DELETE FROM asset_ips WHERE asset_id = ?").bind(id).run();
  }

  // Extra IPs opslaan
  if (rawIps.length > 0) {
      const stmt = context.env.MY_DB.prepare("INSERT INTO asset_ips (asset_id, ip_address, ip_hash) VALUES (?, ?, ?)");
      const batch = [];
      for (const ip of rawIps) { if(!ip) continue; batch.push(stmt.bind(assetId, encrypt(ip, key), hashIP(ip))); }
      if(batch.length > 0) await context.env.MY_DB.batch(batch);
  }

  return new Response(method === 'POST' ? 'Created' : 'Updated', { status: method === 'POST' ? 201 : 200 });
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const { id } = await context.request.json();
    // Cascade delete simulatie
    await context.env.MY_DB.prepare("DELETE FROM assets WHERE id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM asset_ips WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM asset_history WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM vulnerabilities WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM cis_exceptions WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM asset_risks WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM network_layouts WHERE asset_id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM asset_relationships WHERE parent_id = ? OR child_id = ?").bind(id, id).run();
    return new Response('Verwijderd');
}

async function logHistory(context, assetId, type, oldVal, newVal) {
    const user = context.data.user.username;
    await context.env.MY_DB.prepare("INSERT INTO asset_history (asset_id, changed_by, change_type, old_values, new_values, timestamp) VALUES (?, ?, ?, ?, ?, ?)").bind(assetId, user, type, oldVal, newVal, Date.now()).run();
}