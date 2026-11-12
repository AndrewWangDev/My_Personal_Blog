// src/pages/api/auth/register.ts
import type { APIRoute } from 'astro';
// 【只保留这一种官方指定的引入方式】
import { env } from "cloudflare:workers";

import { hashPassword, timingSafeEqualStr } from '../../../utils/password';

import { isAllowedEmailDomain, normalizeEmail, validateUsername } from '../../../utils/validation';

// 【关键：去掉了括号里的 locals 参数，再也不去碰它】
export const POST: APIRoute = async ({ request }) => {
  try {
    const data = await request.formData().catch(() => null);
    if (!data) {
      return new Response(JSON.stringify({ error: "请求格式错误，请填写表单重试" }), { status: 400 });
    }
    const email = normalizeEmail(data.get('email'));
    const username = String(data.get('username') || '').trim();
    const password = data.get('password') as string;
    const verifyCode = String(data.get('verify_code') || '').trim();
    const turnstileResponse = data.get('cf-turnstile-response') as string;

    if (!email || !username || !password || !verifyCode) {
      return new Response(JSON.stringify({ error: "请填写完整注册信息（包含 6 位验证码）" }), { status: 400 });
    }

    const uCheck = validateUsername(username);
    if (!uCheck.valid) {
      return new Response(JSON.stringify({ error: uCheck.error }), { status: 400 });
    }

    if (!turnstileResponse) {
      return new Response(JSON.stringify({ error: "人机验证未完成，请重新点击人机验证框" }), { status: 400 });
    }

    if (!isAllowedEmailDomain(email)) {
      return new Response(JSON.stringify({ error: "仅支持 Gmail, Outlook, Yahoo, Hotmail, iCloud, Proton 邮箱注册，请更换重试" }), { status: 400 });
    }
    const turnstileSecret = (env as any).TURNSTILE_SECRET_KEY;
    if (!turnstileSecret) {
      return new Response(JSON.stringify({ error: "服务器人机验证配置缺失" }), { status: 500 });
    }
    const verifyParams = new URLSearchParams();
    verifyParams.append('secret', turnstileSecret);
    verifyParams.append('response', turnstileResponse);
    const clientIp = request.headers.get('CF-Connecting-IP') || '';
    if (clientIp) verifyParams.append('remoteip', clientIp);

    const turnstileCheck = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: verifyParams,
    });
    const turnstileOutcome = await turnstileCheck.json();
    if (!turnstileOutcome.success) {
      return new Response(JSON.stringify({ error: "人机验证未通过，请重试" }), { status: 400 });
    }

    // --- 数据库操作区 ---
    // 【直接使用 env.DB，再也不写降级兼容】
    const db = env.DB;
    
    if (!db) {
      throw new Error("数据库依然隐身。请确认 wrangler.toml 里的 preview_database_id 已配置并重启了服务。");
    }
    
    const existingUser = await db.prepare('SELECT id FROM users WHERE LOWER(email) = ?').bind(email).first();
    if (existingUser) {
      return new Response(JSON.stringify({ error: "该邮箱已被注册，请直接登录" }), { status: 400 });
    }

    const recentlyDeleted = await db.prepare("SELECT email FROM deleted_users WHERE LOWER(email) = ? AND expires_at > datetime('now')").bind(email).first();
    if (recentlyDeleted) {
      return new Response(JSON.stringify({ error: "该邮箱已被注销且处于保护期内，期间仅能注册一次，请解禁后重试" }), { status: 400 });
    }

    // --- 验证码校验 ---
    const verification = await db.prepare("SELECT code, expires_at FROM email_verifications WHERE LOWER(email) = ?").bind(email).first() as any;
    if (!verification || !timingSafeEqualStr(String(verification.code || ''), verifyCode)) {
      return new Response(JSON.stringify({ error: "验证码错误或已过期" }), { status: 400 });
    }
    if (new Date(verification.expires_at) < new Date()) {
      return new Response(JSON.stringify({ error: "验证码已过期，请重新获取" }), { status: 400 });
    }

    const userId = crypto.randomUUID();
    const hashedPassword = await hashPassword(password);

    await db.batch([
      db.prepare('INSERT INTO users (id, email, username, password_hash, token_version) VALUES (?, ?, ?, ?, 1)').bind(userId, email, username, hashedPassword),
      db.prepare("DELETE FROM email_verifications WHERE LOWER(email) = ?").bind(email)
    ]);

    return new Response(JSON.stringify({ success: true, message: "注册成功！" }), { status: 200 });
    
  } catch (error: any) {
    console.error("【后端入库报错】:", error?.message || error);
    return new Response(JSON.stringify({ error: "注册失败，请稍后重试" }), { status: 500 });
  }
};