import type { APIRoute } from 'astro';
import { env } from "cloudflare:workers";
import { generateRandomChallenge, base64UrlEncode, storeWebAuthnChallenge } from '../../../../utils/webauthn';

export const POST: APIRoute = async ({ request, locals }) => {
  const db = (env as any).DB;
  const user = locals.user;
  if (!user) {
    return new Response(JSON.stringify({ error: "请先登录" }), { status: 401 });
  }

  try {
    const url = new URL(request.url);
    const rpId = url.hostname;
    const challenge = generateRandomChallenge(32);

    // Save challenge in KV (or D1 fallback) with 5-minute TTL
    const sessionKv = (env as any).SESSION;
    await storeWebAuthnChallenge(sessionKv, db, `passkey_reg_${user.id}`, challenge, 300);

    const userIdBytes = new TextEncoder().encode(user.id);
    const userHandle = base64UrlEncode(userIdBytes);

    const options = {
      challenge,
      rp: {
        name: "Andrew Wang Dev",
        id: rpId
      },
      user: {
        id: userHandle,
        name: user.username || user.email,
        displayName: user.username || user.email
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256 (P-256)
        { type: "public-key", alg: -257 }  // RS256
      ],
      timeout: 60000,
      authenticatorSelection: {
        residentKey: "preferred",
        requireResidentKey: false,
        userVerification: "preferred"
      },
      attestation: "none"
    };

    return new Response(JSON.stringify({ success: true, options }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (err: any) {
    console.error("Passkey register options error:", err);
    return new Response(JSON.stringify({ error: "初始化通行密钥注册失败" }), { status: 500 });
  }
};
