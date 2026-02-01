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

// --- API LOGIC ---
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
            const guid = row.subscription_id || row.guid;
            const name = row.subscription_name || row.name;
            const resp = row.responsibles || '';

            if (!guid) continue;

            const item = { name, guid, responsibles: resp };

            if (existingMap.has(guid)) {
                item.old_name = existingMap.get(guid).name;
                report.existing.push(item);
            } else {
                report.new.push(item);
            }
        }
    } 
    else if (type === 'assets') {
        const { results } = await context.env.MY_DB.prepare("SELECT name, ip_hash FROM assets").all();
        const existingNames = new Set(results.map(r => r.name));
        const existingHashes = new Set(results.map(r => r.ip_hash));

        for (const row of rows) {
            const ip = row.privateIP || row.ip_address;
            const subId = row.subscriptionId || row.subscription_id;
            const name = row.name;

            if (!name) continue;

            const item = {
                name: name,
                ip_address: ip,
                subscription_id: subId,
                resource_group: row.resourceGroup || '',
                location: row.location || '',
                type: 'Virtual Machine' 
            };

            if (name.toLowerCase().includes('nic')) item.type = 'Network Interface';
            if (name.toLowerCase().includes('db')) item.type = 'SQL Database';
            if (name.toLowerCase().includes('kv')) item.type = 'Key Vault';

            const ipHash = ip ? hashIP(ip) : null;
            
            if (existingNames.has(name)) {
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
        const chunkSize = 50;
        for (let i = 0; i < batch.length; i += chunkSize) {
            const chunk = batch.slice(i, i + chunkSize);
            await context.env.MY_DB.batch(chunk);
        }
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
            const encSub = encrypt(row.subscription_id, key); // Sla GUID versleuteld op
            
            // AANPASSING: Owner is leeg bij import, tenzij specifiek in CSV (hier default leeg)
            const owner = encrypt('', key); 
            
            await stmt.bind(
                row.name, 
                row.type || 'Imported Resource', 
                encSub, 
                encIp, 
                ipHash, 
                0, // Default CIS score
                'Internal', // Default Classification
                '', // Default Sensitivity
                owner, 
                Date.now()
            ).run();
            count++;
        }
    }

    return Response.json({ status: 'success', count });
}