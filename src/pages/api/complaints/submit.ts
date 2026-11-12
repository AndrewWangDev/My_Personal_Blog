import type { APIRoute } from 'astro';
import { env } from "cloudflare:workers";

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const userId = locals.user?.id;
    if (!userId) {
      return new Response(JSON.stringify({ error: "请先登录" }), { status: 401 });
    }

    const data = await request.formData();
    const targetType = String(data.get('target_type') || '').trim();
    const targetId = String(data.get('target_id') || '').trim();
    const reason = String(data.get('reason') || '').trim();
    const details = String(data.get('details') || '').trim();
    const turnstileResponse = data.get('cf-turnstile-response') as string;

    const ALLOWED_TARGET_TYPES = new Set(['blog', 'news', 'resource']);
    const ALLOWED_REASONS = new Set(['r1', 'r2', 'r3', 'r4', 'r5']);

    if (!targetType || !targetId || !reason || !details) {
      return new Response(JSON.stringify({ error: "请填写完整投诉信息" }), { status: 400 });
    }
    if (!ALLOWED_TARGET_TYPES.has(targetType)) {
      return new Response(JSON.stringify({ error: "无效的投诉目标类型" }), { status: 400 });
    }
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(targetId)) {
      return new Response(JSON.stringify({ error: "无效的投诉目标 ID" }), { status: 400 });
    }
    if (!ALLOWED_REASONS.has(reason)) {
      return new Response(JSON.stringify({ error: "无效的投诉原因" }), { status: 400 });
    }
    if (details.length > 2000) {
      return new Response(JSON.stringify({ error: "投诉详情不能超过 2000 个字符" }), { status: 400 });
    }

    if (!turnstileResponse) {
      return new Response(JSON.stringify({ error: "请完成人机验证" }), { status: 400 });
    }

    // 1. 验证 Turnstile (使用官方推荐的 URLSearchParams 格式与客户端 IP)
    const turnstileSecret = (env as any).TURNSTILE_SECRET_KEY;
    if (!turnstileSecret) {
      return new Response(JSON.stringify({ error: "服务器安全配置未就绪 (Missing Turnstile Secret)" }), { status: 500 });
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

    const db = env.DB;
    
    // 2. 获取每日限制额度
    const settings = await db.prepare("SELECT key, value FROM settings WHERE key IN ('max_user_complaints_daily', 'max_total_complaints_daily')").all();
    let maxUserDaily = 5;
    let maxTotalDaily = 100;
    
    settings.results?.forEach((s: any) => {
      if (s.key === 'max_user_complaints_daily') maxUserDaily = parseInt(s.value, 10);
      if (s.key === 'max_total_complaints_daily') maxTotalDaily = parseInt(s.value, 10);
    });

    // 3. 检查单人额度
    const userDailyCountRow = await db.prepare("SELECT COUNT(*) as count FROM complaints WHERE user_id = ? AND date(created_at) = date('now')").bind(userId).first() as { count: number };
    const userDailyCount = userDailyCountRow ? userDailyCountRow.count : 0;
    
    if (userDailyCount >= maxUserDaily) {
       return new Response(JSON.stringify({ error: "limit_exceeded" }), { status: 403 });
    }

    // 4. 检查总额度
    const totalDailyCountRow = await db.prepare("SELECT COUNT(*) as count FROM complaints WHERE date(created_at) = date('now')").first() as { count: number };
    const totalDailyCount = totalDailyCountRow ? totalDailyCountRow.count : 0;
    
    if (totalDailyCount >= maxTotalDaily) {
       return new Response(JSON.stringify({ error: "limit_exceeded" }), { status: 403 });
    }

    // 5. 插入投诉记录
    await db.prepare(
      'INSERT INTO complaints (user_id, target_type, target_id, reason, details) VALUES (?, ?, ?, ?, ?)'
    ).bind(userId, targetType, targetId, reason, details).run();

    return new Response(JSON.stringify({ success: true }), { status: 200 });

  } catch (error: any) {
    console.error("【投诉提交报错】:", error.message);
    return new Response(JSON.stringify({ error: "提交失败，请稍后重试" }), { status: 500 });
  }
};
