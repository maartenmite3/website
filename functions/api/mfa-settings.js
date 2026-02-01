import * as OTPAuth from "otpauth";

// GET: Genereer een nieuwe secret voor de QR code
export async function onRequestGet(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });

  // Genereer random secret
  const secret = new OTPAuth.Secret({ size: 20 });
  const secretBase32 = secret.base32;

  // Maak de URL voor de QR code
  const totp = new OTPAuth.TOTP({
    issuer: "MijnCloudflareApp",
    label: context.data.user.username,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: secret
  });

  return Response.json({ 
    secret: secretBase32, 
    otpauth_url: totp.toString() 
  });
}

// POST: Activeer MFA na invullen eerste code
export async function onRequestPost(context) {
  if (!context.data.user) return new Response('Unauthorized', { status: 401 });
  
  const { secret, token } = await context.request.json();

  // Check of de code klopt bij de NET gegenereerde secret
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret) });
  const delta = totp.validate({ token, window: 1 });

  if (delta === null) return new Response('Code onjuist', { status: 400 });

  // Sla op in database en zet AAN
  await context.env.MY_DB.prepare("UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?")
    .bind(secret, context.data.user.id)
    .run();

  return new Response('MFA Geactiveerd');
}