export async function onRequestGet(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const url = new URL(context.request.url);
    const mode = url.searchParams.get('mode');

    // Lijst van alle benchmarks ophalen
    if (mode === 'list') {
        const { results } = await context.env.MY_DB.prepare("SELECT * FROM cis_benchmarks ORDER BY name ASC").all();
        return Response.json(results);
    }

    // Specifieke controls ophalen voor een benchmark (voor de dropdown)
    const benchmarkId = url.searchParams.get('benchmark_id');
    if (benchmarkId) {
        const { results } = await context.env.MY_DB.prepare("SELECT id, recommendation_id, title, profile FROM cis_controls WHERE benchmark_id = ?").bind(benchmarkId).all();
        return Response.json(results);
    }

    return new Response('Invalid mode', { status: 400 });
}

export async function onRequestPost(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    
    try {
        const data = await context.request.json();
        
        // 1. Nieuwe Benchmark aanmaken
        const res = await context.env.MY_DB.prepare("INSERT INTO cis_benchmarks (name, uploaded_at) VALUES (?, ?) RETURNING id")
            .bind(data.name, Date.now()).first();
        
        const benchmarkId = res.id;

        // 2. Controls in batch opslaan
        // We verwachten data.rows als array van { id, title, profile, description }
        const stmt = context.env.MY_DB.prepare("INSERT INTO cis_controls (benchmark_id, recommendation_id, title, profile, description) VALUES (?, ?, ?, ?, ?)");
        
        const batch = [];
        // Max 100 per keer ivm D1 limieten, dus we moeten chunken in de frontend of hier loopen
        // Voor veiligheid hier een simpele loop (D1 batch support arrays)
        for (const row of data.rows) {
            batch.push(stmt.bind(benchmarkId, row.id, row.title, row.profile, row.desc));
        }

        // Opsplitsen in chunks van 50 voor performance
        const chunkSize = 50;
        for (let i = 0; i < batch.length; i += chunkSize) {
            await context.env.MY_DB.batch(batch.slice(i, i + chunkSize));
        }

        return new Response('Benchmark Imported', { status: 201 });

    } catch (e) {
        return Response.json({ error: e.message }, { status: 500 });
    }
}