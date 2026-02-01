import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// --- ENCRYPTIE FUNCTIES ---
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

// --- API HANDLERS ---

export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const key = context.env.ENCRYPTION_KEY;

  // Haal ook historie op als daarom gevraagd wordt (?history=asset_id)
  const url = new URL(context.request.url);
  const historyId = url.searchParams.get('history');

  if (historyId) {
      const { results } = await context.env.MY_DB.prepare("SELECT * FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC").bind(historyId).all();
      return Response.json(results);
  }

  const { results } = await context.env.MY_DB.prepare("SELECT * FROM assets ORDER BY created_at DESC").all();

  // Decrypt voor we sturen
  const decryptedResults = results.map(asset => {
      return {
          ...asset,
          // Subscription ID is nu vaak een gekoppeld ID, maar als het tekst was, decrypten we.
          // Voor nu gaan we ervan uit dat subscription_id in assets tabel de GUID of Naam bevat (encrypted).
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

  const encSub = encrypt(data.subscription_id, key); // We slaan de GUID/Ref op
  const encIp = encrypt(data.ip_address, key);
  const encOwner = encrypt(data.owner_contact, key);

  // Data sensitivity kan nu een array zijn, maak er string van
  const sensitivity = Array.isArray(data.data_sensitivity) ? data.data_sensitivity.join(', ') : data.data_sensitivity;

  const res = await context.env.MY_DB.prepare(`
    INSERT INTO assets (name, type, subscription_id, ip_address, cis_score, classification, data_sensitivity, owner_contact, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
  `).bind(data.name, data.type, encSub, encIp, data.cis_score, data.classification, sensitivity, encOwner, Date.now()).first();

  // Log History (Creation)
  await logHistory(context, res.id, 'CREATE', null, JSON.stringify(data));

  return new Response('Asset toegevoegd', { status: 201 });
}

// PUT: Bewerken
export async function onRequestPut(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const key = context.env.ENCRYPTION_KEY;
    const data = await context.request.json();
    const id = data.id;

    // 1. Haal oude data op (voor historie) - Ontsleutel niet nodig voor opslag, maar wel voor loggen
    // We slaan in de historie gewoon de "leesbare" oude versie op, dat is makkelijker lezen.
    const oldAsset = await context.env.MY_DB.prepare("SELECT * FROM assets WHERE id = ?").bind(id).first();
    const readableOld = { ...oldAsset, ip_address: decrypt(oldAsset.ip_address, key) }; // Even snel leesbaar maken voor log

    // 2. Encrypt nieuwe data
    const encSub = encrypt(data.subscription_id, key);
    const encIp = encrypt(data.ip_address, key);
    const encOwner = encrypt(data.owner_contact, key);
    const sensitivity = Array.isArray(data.data_sensitivity) ? data.data_sensitivity.join(', ') : data.data_sensitivity;

    // 3. Update
    await context.env.MY_DB.prepare(`
        UPDATE assets SET name=?, type=?, subscription_id=?, ip_address=?, cis_score=?, classification=?, data_sensitivity=?, owner_contact=?
        WHERE id=?
    `).bind(data.name, data.type, encSub, encIp, data.cis_score, data.classification, sensitivity, encOwner, id).run();

    // 4. Log History
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