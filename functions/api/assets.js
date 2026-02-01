import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// --- HULPFUNCTIES VOOR ENCRYPTIE ---
// We gebruiken AES-256-CBC encryptie.
// De 'key' halen we uit de environment variable.

function encrypt(text, keyString) {
  if (!text) return null;
  // Zorg dat de key precies 32 bytes is (indien te lang/kort, pakken we de eerste 32 of vullen aan)
  // Voor veiligheid: Zorg dat je ENCRYPTION_KEY in Cloudflare lang genoeg is!
  const key = Buffer.alloc(32); 
  key.write(keyString || '');

  const iv = randomBytes(16); // Random startwaarde
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // We slaan op als: IV:ENCRYPTED_TEXT (zodat we de IV weer kunnen gebruiken bij decryptie)
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText, keyString) {
  if (!encryptedText || !encryptedText.includes(':')) return encryptedText; // Als niet encrypted lijkt, stuur origineel terug
  
  try {
      const key = Buffer.alloc(32);
      key.write(keyString || '');

      const textParts = encryptedText.split(':');
      const iv = Buffer.from(textParts.shift(), 'hex');
      const encryptedData = textParts.join(':');
      
      const decipher = createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
  } catch (e) {
      return "[Fout bij ontsleutelen]";
  }
}

// --- DE API ---

export async function onRequestGet(context) {
  // 1. Check Auth (Iedereen met account mag kijken, of wil je alleen Admin?)
  // Laten we zeggen: Iedereen mag kijken (read-only), Admin mag wijzigen.
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });

  const key = context.env.ENCRYPTION_KEY;
  if (!key) return new Response('Server Config Error: Geen Encryptie sleutel', { status: 500 });

  // 2. Haal alles op
  const { results } = await context.env.MY_DB.prepare("SELECT * FROM assets ORDER BY created_at DESC").all();

  // 3. Decrypt de gevoelige velden voordat we ze naar de browser sturen
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
  // Alleen opslaan als je ingelogd bent
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });

  const key = context.env.ENCRYPTION_KEY;
  const { name, type, subscription_id, ip_address, cis_score, classification, data_sensitivity, owner_contact } = await context.request.json();

  if (!name) return new Response('Naam is verplicht', { status: 400 });

  // Encrypt gevoelige data
  const encSub = encrypt(subscription_id, key);
  const encIp = encrypt(ip_address, key);
  const encOwner = encrypt(owner_contact, key);

  await context.env.MY_DB.prepare(`
    INSERT INTO assets (name, type, subscription_id, ip_address, cis_score, classification, data_sensitivity, owner_contact, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(name, type, encSub, encIp, cis_score, classification, data_sensitivity, encOwner, Date.now()).run();

  return new Response('Asset toegevoegd', { status: 201 });
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const { id } = await context.request.json();
    await context.env.MY_DB.prepare("DELETE FROM assets WHERE id = ?").bind(id).run();
    return new Response('Verwijderd');
}