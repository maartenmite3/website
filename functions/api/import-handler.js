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
    
    try {
        const { mode, type, data } = await context.request.json(); 

        if (mode === 'check') {
            return await handleCheck(context, type, data);
        } else if (mode === 'execute') {
            return await handleExecute(context, type, data);
        }
        return new Response('Invalid mode', { status: 400 });
    } catch (e) {
        return new Response('Server Error: ' + e.message, { status: 500 });
    }
}

async function handleCheck(context, type, rows) {
    const report = { new: [], existing: [], conflicts: [] };

    if (type === 'subscriptions') {
        const { results } = await context.env.MY_DB.prepare("SELECT guid, name FROM subscriptions").all();
        const existingMap = new Map(results.map(r => [r.guid, r]));

        for (const row of rows) {
            // MAPPING: Jouw CSV headers -> Database velden
            const guid = row.subscription_id || row.guid; // CSV: subscription_id
            const name = row.subscription_name || row.name; // CSV: subscription_name
            const resp = row.responsibles || '';

            if (!guid) continue; 

            const item = { name, guid, responsibles: resp };

            if (existingMap.has(guid)) {
                report.existing.push(item);
            } else {
                report.new.push(item);
            }
        }
    } 
    else if (type === 'assets') {
        // Haal bestaande op om te checken
        const { results } = await context.env.MY_DB.prepare("SELECT name, ip_hash FROM assets").all();
        const existingNames = new Set(results.map(r => r.name));
        const existingHashes = new Set(results.map(r => r.ip_hash));

        for (const row of rows) {
            // MAPPING: Jouw CSV (resources.csv) -> Database velden
            // CSV headers: name, privateIP, location, resourceGroup, subscriptionId
            
            const ip = row.privateIP || row.ip_address; 
            const subId = row.subscriptionId || row.subscription_id;
            
            if (!row.name) continue; // Skip lege regels

            const item = {
                name: row.name,
                ip_address: ip,
                subscription_id: subId,
                resource_group: row.resourceGroup || '', // Extra info bewaren we niet in DB tenzij we kolom hebben, maar wel handig voor logica
                type: 'Imported Resource' 
            };

            const ipHash = ip ? hashIP(ip) : null;
            
            if (existingNames.has(item.name)) {
                item.reason = "Naam bestaat al";
                report.conflicts.push(item);
            } else if (ipHash && existingHashes.has(ipHash)) {
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
             batch.push(stmt.bind(row.name, row.guid, row.responsibles || '', Date.now()));
        }
        // D1 Batch limit is vaak 100, we doen het simpel:
        for(const q of batch) await q.run(); 
        count = batch.length;
    }
    else if (type === 'assets') {
        const stmt = context.env.MY_DB.prepare(`
            INSERT INTO assets (name, type, subscription_id, ip_address, ip_hash, cis_score, classification, data_sensitivity, owner_contact, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        
        for (const row of rows) {
            const ipHash = hashIP(row.ip_address);
            const encIp = encrypt(row.ip_address, key);
            const encSub = encrypt(row.subscription_id, key); 
            const owner = encrypt('Imported', key); 

            // Probeer type te raden op basis van naam in CSV (bv '-nic' wijst op netwerk interface, vaak VM)
            let assetType = 'Virtual Machine';
            if(row.name && row.name.includes('db')) assetType = 'SQL Database';
            
            await stmt.bind(
                row.name, 
                assetType, 
                encSub, 
                encIp, 
                ipHash, 
                0, // CIS default
                'Internal', // Class default
                '', // Sens default
                owner, 
                Date.now()
            ).run();
            count++;
        }
    }

    return Response.json({ status: 'success', count });
}