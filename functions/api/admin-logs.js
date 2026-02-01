export async function onRequestGet(context) {
  // 1. Beveiliging: Check of gebruiker Admin is
  if (!context.data.user || context.data.user.role !== 'admin') {
    return new Response('Unauthorized', { status: 403 });
  }

  // 2. Haal de nieuwste 50 logs op
  try {
    const { results } = await context.env.MY_DB.prepare(
      "SELECT * FROM logs ORDER BY created_at DESC LIMIT 50"
    ).all();

    return Response.json(results);
  } catch (err) {
    return new Response('Fout bij ophalen logs: ' + err.message, { status: 500 });
  }
}