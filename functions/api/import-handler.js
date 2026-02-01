import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

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
    return createHash('sha256').update(ip.trim()).digest('hex');
}

export async function onRequestPost(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    try {
        const { mode, type, data } = await context.request.json(); 
        if (mode === 'check') return await handleCheck(context, type, data);
        if (mode === 'execute') return await handleExecute(context, type, data);
        return new Response('Invalid mode', { status: 400 });
    } catch (e) { return new Response('Server Error: ' + e.message, { status: 500 }); }
}

async function handleCheck(context, type, rows) {
    const report = { new: [], existing: [], conflicts: [] };

    if (type === 'subscriptions') {
        const { results } = await context.env.MY_DB.prepare("SELECT guid, name FROM subscriptions").all();
        const existingMap = new Map(results.map(r => [r.guid, r]));
        for (const row of rows) {
            const guid = row.subscription_id || row.guid;
            if (!guid) continue;
            const item = { name: row.subscription_name || row.name, guid, responsibles: row.responsibles || '' };
            if (existingMap.has(guid)) { item.old_name = existingMap.get(guid).name; report.existing.push(item); }
            else { report.new.push(item); }
        }
    } 
    else if (type === 'assets') {
        // Haal hashes op van assets en asset_ips
        const r1 = await context.env.MY_DB.prepare("SELECT name, ip_hash FROM assets").all();
        const r2 = await context.env.MY_DB.prepare("SELECT ip_hash FROM asset_ips").all();
        
        const existingNames = new Set(r1.results.map(r => r.name));
        const existingHashes = new Set([...r1.results.map(r => r.ip_hash), ...r2.results.map(r => r.ip_hash)]);

        for (const row of rows) {
            const rawIp = row.privateIP || row.ip_address;
            const name = row.name;
            if (!name) continue;

            const item = {
                name: name,
                ip_address: rawIp, // string, kan "1.1.1.1, 2.2.2.2" zijn
                subscription_id: row.subscriptionId || row.subscription_id,
                type: row.type || 'Virtual Machine'
            };

            // Check naam
            if (existingNames.has(name)) {
                item.reason = "Naam bestaat al";
                report.conflicts.push(item);
                continue;
            }

            // Check IPs
            if (rawIp) {
                const ips = rawIp.split(',').map(s => s.trim());
                let conflict = false;
                for(const ip of ips) {
                    const h = hashIP(ip);
                    if(existingHashes.has(h)) {
                        item.reason = `IP ${ip} bestaat al`;
                        report.conflicts.push(item);
                        conflict = true;
                        break;
                    }
                }
                if(conflict) continue;
            }

            report.new.push(item);
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
        for (const row of rows) batch.push(stmt.bind(row.name, row.guid, row.responsibles || '', Date.now()));
        const chunkSize = 50;
        for (let i = 0; i < batch.length; i += chunkSize) await context.env.MY_DB.batch(batch.slice(i, i + chunkSize));
        count = batch.length;
    }
    else if (type === 'assets') {
        // We moeten Asset aanmaken EN IPs in subtabel zetten
        // D1 batching ondersteunt geen teruggeven van IDs makkelijk in 1 keer, dus we doen dit per stuk of in transacties (transacties support is limited in workers via HTTP, maar wel via batch).
        // Veilige optie: Per stuk inserten.
        
        for (const row of rows) {
            const rawIp = row.ip_address || '';
            const ips = rawIp.split(',').map(s => s.trim()).filter(s => s);
            const primaryIp = ips[0] || '';
            const primaryHash = hashIP(primaryIp);
            
            const encPrimary = encrypt(primaryIp, key);
            const encSub = encrypt(row.subscription_id, key);
            const owner = encrypt('', key);

            // 1. Maak Asset
            const res = await context.env.MY_DB.prepare(`
                INSERT INTO assets (name, type, subscription_id, ip_address, ip_hash, cis_score, classification, data_sensitivity, owner_contact, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
            `).bind(row.name, row.type, encSub, encPrimary, primaryHash, 0, 'Internal', '', owner, Date.now()).first();

            // 2. Maak Asset IPs
            if (res && res.id && ips.length > 0) {
                const batch = [];
                const stmt = context.env.MY_DB.prepare("INSERT INTO asset_ips (asset_id, ip_address, ip_hash) VALUES (?, ?, ?)");
                for(const ip of ips) {
                    batch.push(stmt.bind(res.id, encrypt(ip, key), hashIP(ip)));
                }
                await context.env.MY_DB.batch(batch);
            }
            count++;
        }
    }
    return Response.json({ status: 'success', count });
}