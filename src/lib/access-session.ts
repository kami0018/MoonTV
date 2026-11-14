const SESSION_DURATION_SECONDS = 60 * 60 * 24 * 7;
const encoder = new TextEncoder();

async function sessionKey(secret: string) {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

export const accessSessionCookie = {
  name: 'moontv-session',
  maxAge: SESSION_DURATION_SECONDS,
  httpOnly: true,
  sameSite: 'lax',
  path: '/',
} as const;

export async function issueAccessSession(secret: string) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_DURATION_SECONDS;
  const payload = `${expires}.${crypto.randomUUID()}`;
  const signature = await crypto.subtle.sign(
    'HMAC',
    await sessionKey(secret),
    encoder.encode(`moontv-local-session:${payload}`),
  );
  const hex = Array.from(new Uint8Array(signature), (n) =>
    n.toString(16).padStart(2, '0'),
  ).join('');
  return `${payload}.${hex}`;
}

export async function verifyAccessSession(
  value: string | undefined,
  secret: string | undefined,
) {
  if (!value || !secret) return false;
  const match = /^(\d{1,12})\.([\da-f-]{36})\.([\da-f]{64})$/.exec(value);
  if (!match) return false;
  const [, expires, id, hex] = match;
  if (Number(expires) <= Math.floor(Date.now() / 1000)) return false;
  const signature = Uint8Array.from(hex.match(/.{2}/g) ?? [], (byte) =>
    parseInt(byte, 16),
  );
  return crypto.subtle.verify(
    'HMAC',
    await sessionKey(secret),
    signature,
    encoder.encode(`moontv-local-session:${expires}.${id}`),
  );
}
