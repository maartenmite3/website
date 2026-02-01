export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const { results } = await context.env.MY_DB.prepare("SELECT * FROM subscriptions ORDER BY name ASC").all();
  return Response.json(results);
}

export async function onRequestPost(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const { name, guid, responsibles } = await context.request.json();
  
  // Check dubbele GUID
  const existing = await context.env.MY_DB.prepare("SELECT id FROM subscriptions WHERE guid = ?").bind(guid).first();
  if (existing) return new Response('Er bestaat al een subscriptie met deze GUID', { status: 409 });

  await context.env.MY_DB.prepare(
    "INSERT INTO subscriptions (name, guid, responsibles, created_at) VALUES (?, ?, ?, ?)"
  ).bind(name, guid, responsibles, Date.now()).run();
  
  return new Response('Added', { status: 201 });
}

// NIEUW: Bewerken (PUT)
export async function onRequestPut(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const { id, name, guid, responsibles } = await context.request.json();

  // Check of GUID al bestaat bij IEMAND ANDERS
  const existing = await context.env.MY_DB.prepare("SELECT id FROM subscriptions WHERE guid = ? AND id != ?").bind(guid, id).first();
  if (existing) return new Response('GUID is al in gebruik bij een andere subscriptie', { status: 409 });

  await context.env.MY_DB.prepare(
    "UPDATE subscriptions SET name = ?, guid = ?, responsibles = ? WHERE id = ?"
  ).bind(name, guid, responsibles, id).run();

  return new Response('Updated', { status: 200 });
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const { id } = await context.request.json();
    await context.env.MY_DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run();
    return new Response('Deleted');
}