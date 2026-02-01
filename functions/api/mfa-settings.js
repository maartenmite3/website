import * as OTPAuth from "otpauth";

// GET: Genereer QR Secret
export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });

  const secret = new OTPAuth.Secret({ size: 20 });
  const totp = new OTPAuth.TOTP({
    issuer: "MijnCloudflareApp",
    label: context.data.user.username,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: secret
  });

  return Response.json({ secret: secret.base32, otpauth_url: totp.toString() });
}

// POST: Activeer MFA
export async function onRequestPost(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  
  const { secret, token } = await context.request.json();
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret) });
  
  if (totp.validate({ token, window: 1 }) === null) {
    return new Response('Code onjuist', { status: 400 });
  }

  await context.env.MY_DB.prepare("UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?")
    .bind(secret, context.data.user.id)
    .run();

  return new Response('MFA Geactiveerd');
}

// DELETE: Zet MFA UIT (NIEUW)
export async function onRequestDelete(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });

  // Zet mfa_enabled op 0 en verwijder de secret
  await context.env.MY_DB.prepare("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?")
    .bind(context.data.user.id)
    .run();

  return new Response('MFA Uitgeschakeld');
}