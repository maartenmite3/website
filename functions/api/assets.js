import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

// --- ENCRYPTIE & HASHING FUNCTIES ---

// 1. Encryptie (Voor veilige opslag - omkeerbaar)
function encrypt(text, keyString) {
  if (!text) return null;
  const key = Buffer.alloc(32); key.write(keyString || '');
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// 2. Decryptie (Voor weergave - omkeerbaar)
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

// 3. Hashing (Voor uniekheid check - NIET omkeerbaar, wel vergelijkbaar)
function hashIP(ip) {
    if (!ip) return null;
    return createHash('sha256').update(ip).digest('hex');
}

// --- API HANDLERS ---

export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const key = context.env.ENCRYPTION_KEY;

  // Historie ophalen?
  const url = new URL(context.request.url);
  const historyId = url.searchParams.get('history');
  if (historyId) {
      const { results } = await context.env.MY_DB.prepare("SELECT * FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC").bind(historyId).all();
      return Response.json(results);
  }

  // Assets ophalen
  const { results } = await context.env.MY_DB.prepare("SELECT * FROM assets ORDER BY created_at DESC").all();

  const decryptedResults = results.map(asset => {
      return {
          ...asset,
          subscription_id: decrypt(asset.subscription_id, key),
          ip_address: decrypt(asset.ip_address, key),
          owner_contact: decrypt(asset.owner_contact, key)
      };
  });

  return Response.json(decryptedResults);
}

export async function onRequestPost(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const key = context.env.ENCRYPTION_KEY;
  const data = await context.request.json();

  // --- VALIDATIE CHECK (NIEUW) ---
  const ipHash = hashIP(data.ip_address);
  
  // Zoek of er al een asset is met deze NAAM of IP HASH
  const existing = await context.env.MY_DB.prepare(
      "SELECT id, name, ip_hash FROM assets WHERE name = ? OR ip_hash = ?"
  ).bind(data.name, ipHash).first();

  if (existing) {
      if (existing.name === data.name) return new Response('Er bestaat al een asset met deze naam.', { status: 409 });
      if (existing.ip_hash === ipHash) return new Response('Er bestaat al een asset met dit IP adres.', { status: 409 });
  }
  // -------------------------------

  const encSub = encrypt(data.subscription_id, key);
  const encIp = encrypt(data.ip_address, key);
  const encOwner = encrypt(data.owner_contact, key);
  const sensitivity = Array.isArray(data.data_sensitivity) ? data.data_sensitivity.join(', ') : data.data_sensitivity;

  const res = await context.env.MY_DB.prepare(`
    INSERT INTO assets (name, type, subscription_id, ip_address, ip_hash, cis_score, classification, data_sensitivity, owner_contact, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
  `).bind(data.name, data.type, encSub, encIp, ipHash, data.cis_score, data.classification, sensitivity, encOwner, Date.now()).first();

  await logHistory(context, res.id, 'CREATE', null, JSON.stringify(data));

  return new Response('Asset toegevoegd', { status: 201 });
}

export async function onRequestPut(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const key = context.env.ENCRYPTION_KEY;
    const data = await context.request.json();
    const id = data.id;

    // --- VALIDATIE CHECK (NIEUW) ---
    // Bij update moeten we checken of de naam/ip bestaat, MAAR niet als het de asset zelf is (id != id)
    const ipHash = hashIP(data.ip_address);
    
    const existing = await context.env.MY_DB.prepare(
        "SELECT id, name, ip_hash FROM assets WHERE (name = ? OR ip_hash = ?) AND id != ?"
    ).bind(data.name, ipHash, id).first();

    if (existing) {
        if (existing.name === data.name) return new Response('Naam is al in gebruik bij een andere asset.', { status: 409 });
        if (existing.ip_hash === ipHash) return new Response('IP is al in gebruik bij een andere asset.', { status: 409 });
    }
    // -------------------------------

    const oldAsset = await context.env.MY_DB.prepare("SELECT * FROM assets WHERE id = ?").bind(id).first();
    const readableOld = { ...oldAsset, ip_address: decrypt(oldAsset.ip_address, key) };

    const encSub = encrypt(data.subscription_id, key);
    const encIp = encrypt(data.ip_address, key);
    const encOwner = encrypt(data.owner_contact, key);
    const sensitivity = Array.isArray(data.data_sensitivity) ? data.data_sensitivity.join(', ') : data.data_sensitivity;

    await context.env.MY_DB.prepare(`
        UPDATE assets SET name=?, type=?, subscription_id=?, ip_address=?, ip_hash=?, cis_score=?, classification=?, data_sensitivity=?, owner_contact=?
        WHERE id=?
    `).bind(data.name, data.type, encSub, encIp, ipHash, data.cis_score, data.classification, sensitivity, encOwner, id).run();

    await logHistory(context, id, 'UPDATE', JSON.stringify(readableOld), JSON.stringify(data));

    return new Response('Updated');
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const { id } = await context.request.json();
    await context.env.MY_DB.prepare("DELETE FROM assets WHERE id = ?").bind(id).run();
    await context.env.MY_DB.prepare("DELETE FROM asset_history WHERE asset_id = ?").bind(id).run();
    return new Response('Verwijderd');
}

async function logHistory(context, assetId, type, oldVal, newVal) {
    const user = context.data.user.username;
    await context.env.MY_DB.prepare(
        "INSERT INTO asset_history (asset_id, changed_by, change_type, old_values, new_values, timestamp) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(assetId, user, type, oldVal, newVal, Date.now()).run();
}