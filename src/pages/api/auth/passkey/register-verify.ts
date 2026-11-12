import type { APIRoute } from 'astro';
import { env } from "cloudflare:workers";
import {
  parseClientDataJSON,
  parseAndVerifyAttestation,
  consumeWebAuthnChallenge
} from '../../../../utils/webauthn';
import { timingSafeEqualStr } from '../../../../utils/password';

export const POST: APIRoute = async ({ request, cookies, locals }) => {
  const db = (env as any).DB;
  const user = locals.user;
  if (!user) {
    return new Response(JSON.stringify({ error: "请先登录" }), { status: 401 });
  }

  try {
    const data = await request.json();
    const { id, response, name } = data;

    if (!id || typeof id !== 'string' || !response || !response.clientDataJSON || !response.attestationObject) {
      return new Response(JSON.stringify({ error: "无效的通行密钥凭据数据" }), { status: 400 });
    }

    const sessionKv = (env as any).SESSION;
    if (!db) {
      return new Response(JSON.stringify({ error: "数据库不可用" }), { status: 500 });
    }

    // 1. Verify challenge strictly from server-side KV or D1 (never trust client challenge cookies)
    cookies.delete('passkey_reg_ch', { path: '/' });
    const expectedChallenge = await consumeWebAuthnChallenge(sessionKv, db, `passkey_reg_${user.id}`);
    if (!expectedChallenge) {
      return new Response(JSON.stringify({ error: "通行密钥注册挑战码已失效，请重试" }), { status: 400 });
    }

    const clientData = parseClientDataJSON(response.clientDataJSON);

    if (!timingSafeEqualStr(clientData.challenge || '', expectedChallenge)) {
      return new Response(JSON.stringify({ error: "通行密钥挑战码验证失败，请重试" }), { status: 400 });
    }

    if (clientData.type !== 'webauthn.create') {
      return new Response(JSON.stringify({ error: "凭据操作类型不匹配" }), { status: 400 });
    }

    // Origin verification
    const url = new URL(request.url);
    if (clientData.origin !== url.origin) {
      return new Response(JSON.stringify({ error: "来源域名校验失败" }), { status: 403 });
    }

    // 2. Parse & cryptographically validate attestationObject (rpIdHash, flags, credentialId, COSE key)
    let publicKeySpki = '';
    let initialCounter = 0;
    try {
      const attResult = await parseAndVerifyAttestation(response.attestationObject, url.hostname, id);
      publicKeySpki = attResult.publicKeySpki;
      initialCounter = attResult.signCount;
    } catch (attErr: any) {
      console.error("Attestation parsing/verification failed:", attErr);
      return new Response(JSON.stringify({ error: "通行密钥凭据解析或来源校验失败" }), { status: 400 });
    }

    // 3. Enforce ownership check: never overwrite an existing credential ID (prevents cross-account takeover)
    const existingCred = await db.prepare('SELECT user_id FROM user_passkeys WHERE id = ?').bind(id).first();
    if (existingCred) {
      return new Response(JSON.stringify({ error: "该通行密钥已绑定或存在冲突，请更换设备重试" }), { status: 409 });
    }

    const rawName = typeof name === 'string' ? name.trim() : '';
    const keyName = rawName ? rawName.slice(0, 64) : "Passkey (" + new Date().toLocaleDateString() + ")";
    const transports = Array.isArray(response.transports) ? response.transports.slice(0, 8) : ['internal'];

    await db.prepare(`
      INSERT INTO user_passkeys (id, user_id, name, public_key, counter, transports, created_at)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(
      id,
      user.id,
      keyName,
      publicKeySpki,
      initialCounter,
      JSON.stringify(transports)
    ).run();

    return new Response(JSON.stringify({
      success: true,
      message: "通行密钥添加成功！",
      passkey: { id, name: keyName }
    }), { status: 201 });

  } catch (err: any) {
    console.error("Passkey register verification error:", err);
    return new Response(JSON.stringify({ error: "验证通行密钥注册失败" }), { status: 500 });
  }
};
