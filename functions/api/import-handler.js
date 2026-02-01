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

function hashIP(ip) {
    if (!ip) return null;
    return createHash('sha256').update(ip).digest('hex');
}

// --- API ---

export async function onRequestPost(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    
    const { mode, type, data } = await context.request.json(); 
    // mode: 'check' of 'execute'
    // type: 'subscriptions' of 'assets'
    // data: Array van objecten uit de CSV

    if (mode === 'check') {
        return await handleCheck(context, type, data);
    } else if (mode === 'execute') {
        return await handleExecute(context, type, data);
    }
    
    return new Response('Invalid mode', { status: 400 });
}

async function handleCheck(context, type, rows) {
    const report = { new: [], existing: [], conflicts: [] };

    if (type === 'subscriptions') {
        // Haal alle bestaande GUIDs op
        const { results } = await context.env.MY_DB.prepare("SELECT guid, name FROM subscriptions").all();
        const existingMap = new Map(results.map(r => [r.guid, r]));

        for (const row of rows) {
            // CSV mapping: subscription_name, subscription_id
            const item = { 
                name: row.subscription_name || row.name, 
                guid: row.subscription_id || row.guid,
                responsibles: row.responsibles || '' 
            };

            if (!item.guid) continue; // Skip lege regels

            if (existingMap.has(item.guid)) {
                // Bestaat al: Check of naam anders is (Update?) of identiek (Skip)
                const current = existingMap.get(item.guid);
                item.old_name = current.name;
                report.existing.push(item);
            } else {
                report.new.push(item);
            }
        }
    } 
    else if (type === 'assets') {
        // Assets checken is lastiger door encryptie. We gebruiken de hashIP voor IP checks en Naam voor naam checks.
        // Omdat we niet 1000 queries willen doen, halen we namen en ip_hashes op.
        const { results } = await context.env.MY_DB.prepare("SELECT name, ip_hash FROM assets").all();
        const existingNames = new Set(results.map(r => r.name));
        const existingHashes = new Set(results.map(r => r.ip_hash));

        for (const row of rows) {
            // CSV Mapping: name, privateIP, subscriptionId
            const ip = row.privateIP || row.ip_address || row.ip;
            const item = {
                name: row.name,
                ip_address: ip,
                subscription_id: row.subscriptionId || row.subscription_id,
                resource_group: row.resourceGroup || '',
                location: row.location || '',
                type: 'Imported Resource' // Default type
            };

            if (!item.name || !item.ip_address) continue;

            const ipHash = hashIP(item.ip_address);
            
            if (existingNames.has(item.name)) {
                item.reason = "Naam bestaat al";
                report.conflicts.push(item);
            } else if (existingHashes.has(ipHash)) {
                item.reason = "IP bestaat al";
                report.conflicts.push(item);
            } else {
                report.new.push(item);
            }
        }
    }

    return Response.json(report);
}

async function handleExecute(context, type, rows) {
    const key = context.env.ENCRYPTION_KEY;
    let count = 0;

    if (type === 'subscriptions') {
        const stmt = context.env.MY_DB.prepare("INSERT INTO subscriptions (name, guid, responsibles, created_at) VALUES (?, ?, ?, ?)");
        const batch = [];
        
        for (const row of rows) {
             // We doen hier INSERT OR REPLACE of gewoon INSERT en negeren fouten in UI logic
             // Simpelheid: We voegen alleen de "nieuwe" toe die de UI doorstuurt
             batch.push(stmt.bind(row.name, row.guid, row.responsibles, Date.now()));
        }
        if (batch.length > 0) await context.env.MY_DB.batch(batch);
        count = batch.length;
    }
    else if (type === 'assets') {
        const stmt = context.env.MY_DB.prepare(`
            INSERT INTO assets (name, type, subscription_id, ip_address, ip_hash, cis_score, classification, data_sensitivity, owner_contact, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        const batch = [];

        for (const row of rows) {
            const ipHash = hashIP(row.ip_address);
            const encIp = encrypt(row.ip_address, key);
            const encSub = encrypt(row.subscription_id, key); // Sla subscriptionId encrypted op
            
            // Default waarden voor import
            const cis = 0;
            const classification = 'Internal'; // Default
            const sens = '';
            const owner = encrypt('Import', key); 
            // Type kunnen we proberen te raden of default
            const assetType = 'Virtual Machine'; // Aanname op basis van CSV voorbeeld (NICs horen vaak bij VMs)

            batch.push(stmt.bind(
                row.name, 
                assetType, 
                encSub, 
                encIp, 
                ipHash, 
                cis, 
                classification, 
                sens, 
                owner, 
                Date.now()
            ));
        }
        if (batch.length > 0) await context.env.MY_DB.batch(batch);
        count = batch.length;
    }

    return Response.json({ status: 'success', count });
}