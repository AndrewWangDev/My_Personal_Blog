// src/utils/webauthn.ts
// WebAuthn / Passkey validation utilities for Cloudflare Workers
import { timingSafeEqualStr } from './password';

export function base64UrlEncode(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function base64UrlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function generateRandomChallenge(length = 32): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

// Extract and verify challenge from clientDataJSON
export function parseClientDataJSON(clientDataJSONBase64: string): { challenge: string; type: string; origin: string } {
  const bytes = base64UrlDecode(clientDataJSONBase64);
  const decoder = new TextDecoder('utf-8');
  const jsonStr = decoder.decode(bytes);
  const clientData = JSON.parse(jsonStr);
  return {
    challenge: clientData.challenge,
    type: clientData.type,
    origin: clientData.origin
  };
}

// Parse authenticatorData to extract rpIdHash, flags, and signCount
export function parseAuthenticatorData(authenticatorDataBase64: string): {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  bytes: Uint8Array;
} {
  const bytes = base64UrlDecode(authenticatorDataBase64);
  if (bytes.length < 37) {
    throw new Error('Invalid authenticatorData length');
  }
  const rpIdHash = bytes.slice(0, 32);
  const flags = bytes[32];
  const signCount = ((bytes[33] << 24) | (bytes[34] << 16) | (bytes[35] << 8) | bytes[36]) >>> 0;
  return { rpIdHash, flags, signCount, bytes };
}

export async function verifyRpIdHash(rpIdHash: Uint8Array, expectedRpId: string): Promise<boolean> {
  if (rpIdHash.length !== 32 || !expectedRpId) return false;
  const expectedBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expectedRpId));
  const expected = new Uint8Array(expectedBuffer);
  let diff = 0;
  for (let i = 0; i < 32; i++) {
    diff |= rpIdHash[i] ^ expected[i];
  }
  return diff === 0;
}

// ========== Minimal RFC 8949 CBOR Decoder (for WebAuthn attestationObject & COSE keys) ==========
function decodeCborItem(bytes: Uint8Array, state: { offset: number }): any {
  if (state.offset >= bytes.length) throw new Error('Unexpected end of CBOR input');
  const initial = bytes[state.offset++];
  const majorType = initial >> 5;
  const additional = initial & 0x1f;

  const readLength = (add: number): number => {
    if (add < 24) return add;
    if (add === 24) {
      if (state.offset + 1 > bytes.length) throw new Error('CBOR truncated');
      return bytes[state.offset++];
    }
    if (add === 25) {
      if (state.offset + 2 > bytes.length) throw new Error('CBOR truncated');
      const v = (bytes[state.offset] << 8) | bytes[state.offset + 1];
      state.offset += 2;
      return v;
    }
    if (add === 26) {
      if (state.offset + 4 > bytes.length) throw new Error('CBOR truncated');
      const v =
        ((bytes[state.offset] << 24) |
          (bytes[state.offset + 1] << 16) |
          (bytes[state.offset + 2] << 8) |
          bytes[state.offset + 3]) >>> 0;
      state.offset += 4;
      return v;
    }
    throw new Error('Unsupported CBOR length encoding');
  };

  if (majorType === 0) {
    return readLength(additional);
  }
  if (majorType === 1) {
    return -1 - readLength(additional);
  }
  if (majorType === 2) {
    const len = readLength(additional);
    if (state.offset + len > bytes.length) throw new Error('CBOR byte string truncated');
    const slice = bytes.slice(state.offset, state.offset + len);
    state.offset += len;
    return slice;
  }
  if (majorType === 3) {
    const len = readLength(additional);
    if (state.offset + len > bytes.length) throw new Error('CBOR text string truncated');
    const slice = bytes.slice(state.offset, state.offset + len);
    state.offset += len;
    return new TextDecoder('utf-8').decode(slice);
  }
  if (majorType === 4) {
    const len = readLength(additional);
    const arr = [];
    for (let i = 0; i < len; i++) {
      arr.push(decodeCborItem(bytes, state));
    }
    return arr;
  }
  if (majorType === 5) {
    const len = readLength(additional);
    const map = new Map<any, any>();
    for (let i = 0; i < len; i++) {
      const k = decodeCborItem(bytes, state);
      const v = decodeCborItem(bytes, state);
      map.set(k, v);
    }
    return map;
  }
  if (majorType === 6) {
    readLength(additional);
    return decodeCborItem(bytes, state);
  }
  if (majorType === 7) {
    if (additional === 20) return false;
    if (additional === 21) return true;
    if (additional === 22) return null;
    if (additional === 23) return undefined;
  }
  throw new Error(`Unsupported CBOR major type: ${majorType}`);
}

function encodeDerLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  if (len <= 0xff) return new Uint8Array([0x81, len]);
  return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function encodeDerTlv(tag: number, value: Uint8Array): Uint8Array {
  const lenBytes = encodeDerLength(value.length);
  const out = new Uint8Array(1 + lenBytes.length + value.length);
  out[0] = tag;
  out.set(lenBytes, 1);
  out.set(value, 1 + lenBytes.length);
  return out;
}

function encodeDerPositiveInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  const trimmed = bytes.slice(start);
  if (trimmed[0] & 0x80) {
    const padded = new Uint8Array(trimmed.length + 1);
    padded[0] = 0x00;
    padded.set(trimmed, 1);
    return encodeDerTlv(0x02, padded);
  }
  return encodeDerTlv(0x02, trimmed);
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

async function coseKeyToSpkiBase64Url(coseMap: Map<any, any>): Promise<string> {
  const kty = coseMap.get(1);
  const alg = coseMap.get(3);

  // EC2 (P-256, alg -7)
  if (kty === 2 && alg === -7) {
    const crv = coseMap.get(-1);
    const x = coseMap.get(-2);
    const y = coseMap.get(-3);
    if (crv !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
      throw new Error('Invalid EC2 P-256 COSE key parameters');
    }
    const ecPoint = concatBytes(new Uint8Array([0x04]), x, y);
    // SPKI header for id-ecPublicKey (1.2.840.10045.2.1) + prime256v1 (1.2.840.10045.3.1.7)
    const spkiPrefix = new Uint8Array([
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ]);
    const spki = concatBytes(spkiPrefix, ecPoint);
    await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return base64UrlEncode(spki);
  }

  // RSA (RS256, alg -257)
  if (kty === 3 && alg === -257) {
    const n = coseMap.get(-1);
    const e = coseMap.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array) || n.length < 128) {
      throw new Error('Invalid RSA COSE key parameters');
    }
    const rsaPubKey = encodeDerTlv(0x30, concatBytes(encodeDerPositiveInteger(n), encodeDerPositiveInteger(e)));
    const rsaAlgId = new Uint8Array([
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ]);
    const bitString = encodeDerTlv(0x03, concatBytes(new Uint8Array([0x00]), rsaPubKey));
    const spki = encodeDerTlv(0x30, concatBytes(rsaAlgId, bitString));
    await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    return base64UrlEncode(spki);
  }

  throw new Error(`Unsupported WebAuthn COSE key type/alg: kty=${kty}, alg=${alg}`);
}

export async function parseAndVerifyAttestation(
  attestationObjectBase64: string,
  expectedRpId: string,
  expectedCredentialId: string
): Promise<{ publicKeySpki: string; signCount: number }> {
  const attBytes = base64UrlDecode(attestationObjectBase64);
  const attObj = decodeCborItem(attBytes, { offset: 0 });
  if (!(attObj instanceof Map)) {
    throw new Error('Invalid attestationObject CBOR map');
  }
  const authData = attObj.get('authData');
  if (!(authData instanceof Uint8Array) || authData.length < 55) {
    throw new Error('Missing or truncated authData in attestationObject');
  }

  const rpIdHash = authData.slice(0, 32);
  if (!(await verifyRpIdHash(rpIdHash, expectedRpId))) {
    throw new Error('WebAuthn rpIdHash mismatch');
  }

  const flags = authData[32];
  // Require User Present (0x01) and Attested Credential Data (0x40)
  if (!(flags & 0x01) || !(flags & 0x40)) {
    throw new Error('WebAuthn attestation flags missing UP or AT');
  }

  const signCount = ((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]) >>> 0;
  const credIdLen = (authData[53] << 8) | authData[54];
  if (credIdLen <= 0 || 55 + credIdLen >= authData.length) {
    throw new Error('Invalid credentialId length in authData');
  }

  const credIdBytes = authData.slice(55, 55 + credIdLen);
  const parsedCredentialId = base64UrlEncode(credIdBytes);
  if (!timingSafeEqualStr(parsedCredentialId, expectedCredentialId)) {
    throw new Error('Credential ID mismatch with attestedCredentialData');
  }

  const coseState = { offset: 55 + credIdLen };
  const coseKey = decodeCborItem(authData, coseState);
  if (!(coseKey instanceof Map)) {
    throw new Error('Invalid COSE public key in authData');
  }

  const publicKeySpki = await coseKeyToSpkiBase64Url(coseKey);
  return { publicKeySpki, signCount };
}

// ========== Server-Side Challenge Storage (KV primary, D1 fallback, zero client cookie trust) ==========
export async function storeWebAuthnChallenge(
  kv: any,
  db: any,
  key: string,
  challenge: string,
  ttlSeconds = 300
): Promise<void> {
  if (kv) {
    await kv.put(key, challenge, { expirationTtl: ttlSeconds });
    return;
  }
  if (!db) {
    throw new Error('Neither SESSION KV nor DB binding is available for WebAuthn challenge storage');
  }
  await db.prepare(
    'CREATE TABLE IF NOT EXISTS webauthn_challenges (id TEXT PRIMARY KEY, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL)'
  ).run();
  const now = Date.now();
  const expiresAt = now + ttlSeconds * 1000;
  await db.batch([
    db.prepare('DELETE FROM webauthn_challenges WHERE expires_at < ?').bind(now),
    db.prepare('INSERT OR REPLACE INTO webauthn_challenges (id, challenge, expires_at) VALUES (?, ?, ?)').bind(key, challenge, expiresAt),
  ]);
}

export async function consumeWebAuthnChallenge(kv: any, db: any, key: string): Promise<string> {
  if (kv) {
    const val = (await kv.get(key)) || '';
    if (val) await kv.delete(key);
    return val;
  }
  if (!db) {
    throw new Error('Neither SESSION KV nor DB binding is available for WebAuthn challenge verification');
  }
  await db.prepare(
    'CREATE TABLE IF NOT EXISTS webauthn_challenges (id TEXT PRIMARY KEY, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL)'
  ).run();
  const row = await db.prepare('SELECT challenge, expires_at FROM webauthn_challenges WHERE id = ?').bind(key).first();
  await db.prepare('DELETE FROM webauthn_challenges WHERE id = ?').bind(key).run();
  if (!row || Number(row.expires_at) < Date.now()) {
    return '';
  }
  return String(row.challenge || '');
}

// Convert SPKI or raw public key and verify signature using Web Crypto
export async function verifySignature(
  publicKeySpkiBase64: string,
  authenticatorDataBase64: string,
  clientDataJSONBase64: string,
  signatureBase64: string
): Promise<boolean> {
  try {
    const spkiBytes = base64UrlDecode(publicKeySpkiBase64);
    const authDataBytes = base64UrlDecode(authenticatorDataBase64);
    const clientDataBytes = base64UrlDecode(clientDataJSONBase64);
    const signatureBytes = base64UrlDecode(signatureBase64);

    // Compute SHA-256 of clientDataJSON
    const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataBytes);

    // Concatenate authenticatorData + clientDataHash
    const signedData = new Uint8Array(authDataBytes.length + clientDataHash.byteLength);
    signedData.set(authDataBytes, 0);
    signedData.set(new Uint8Array(clientDataHash), authDataBytes.length);

    // Try importing as ECDSA P-256 first (-7 in WebAuthn)
    try {
      const cryptoKey = await crypto.subtle.importKey(
        'spki',
        spkiBytes,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );

      // WebAuthn signature for ES256 is ASN.1 DER encoded in standard authenticators.
      // Web Crypto expects raw R || S (64 bytes). We convert DER to raw IEEE P1363.
      const rawSignature = derToRawSignature(signatureBytes);

      const isValid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        cryptoKey,
        rawSignature,
        signedData
      );

      if (isValid) return true;
    } catch {
      // If ECDSA import fails, try RSA (RS256)
    }

    // Fallback: Try RS256 (-257)
    try {
      const cryptoKeyRsa = await crypto.subtle.importKey(
        'spki',
        spkiBytes,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      );

      const isValidRsa = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        cryptoKeyRsa,
        signatureBytes,
        signedData
      );

      if (isValidRsa) return true;
    } catch {}

    return false;
  } catch (err) {
    console.error('Passkey signature verification error:', err);
    return false;
  }
}

// Convert ASN.1 DER ECDSA signature to IEEE P1363 (64 bytes R || S)
function derToRawSignature(derBytes: Uint8Array): Uint8Array {
  if (derBytes.length === 64) {
    return derBytes; // Already raw
  }
  try {
    let offset = 2; // Skip 0x30 and total length
    if (derBytes[offset] === 0x02) {
      // First integer R
      offset++;
      const rLen = derBytes[offset++];
      let r = derBytes.slice(offset, offset + rLen);
      offset += rLen;

      // Second integer S
      if (derBytes[offset++] === 0x02) {
        const sLen = derBytes[offset++];
        let s = derBytes.slice(offset, offset + sLen);

        // Strip leading zeros if 33 bytes
        if (r.length === 33 && r[0] === 0) r = r.slice(1);
        if (s.length === 33 && s[0] === 0) s = s.slice(1);

        const raw = new Uint8Array(64);
        raw.set(r, 32 - r.length);
        raw.set(s, 64 - s.length);
        return raw;
      }
    }
  } catch {}
  return derBytes;
}
