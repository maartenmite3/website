import * as OTPAuth from "otpauth";

export async function onRequestPost(context) {
  const { token } = await context.request.json(); // De 6-cijferige code

  // 1. Haal de sessie op (die staat op pending_mfa)
  const cookie = context.request.headers.get('Cookie');
  const sessionKey = cookie?.match(/session_id=([^;]+)/)?.[1];
  if (!sessionKey) return new Response('Geen sessie', { status: 401 });

  // 2. Haal user en secret op
  const result = await context.env.MY_DB.prepare(`
    SELECT users.mfa_secret, sessions.id as session_id 
    FROM sessions 
    JOIN users ON sessions.user_id = users.id 
    WHERE sessions.id = ?
  `).bind(sessionKey).first();

  if (!result || !result.mfa_secret) return new Response('Fout', { status: 400 });

  // 3. Valideer de code met de library
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(result.mfa_secret) });
  const delta = totp.validate({ token: token, window: 1 }); // window 1 = mag ietsje afwijken in tijd

  if (delta === null) {
    return new Response('Code onjuist', { status: 401 });
  }

  // 4. Code klopt! Zet sessie op active
  await context.env.MY_DB.prepare("UPDATE sessions SET status = 'active' WHERE id = ?").bind(sessionKey).run();

  return new Response('OK', { status: 200 });
}