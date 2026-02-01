export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const { results } = await context.env.MY_DB.prepare("SELECT * FROM subscriptions ORDER BY name ASC").all();
  return Response.json(results);
}

export async function onRequestPost(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  const { name, guid, responsibles } = await context.request.json();
  
  await context.env.MY_DB.prepare(
    "INSERT INTO subscriptions (name, guid, responsibles, created_at) VALUES (?, ?, ?, ?)"
  ).bind(name, guid, responsibles, Date.now()).run();
  
  return new Response('Added', { status: 201 });
}

export async function onRequestDelete(context) {
    if (!context.data.user) return new Response('Unauthorized', { status: 401 });
    const { id } = await context.request.json();
    await context.env.MY_DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run();
    return new Response('Deleted');
}