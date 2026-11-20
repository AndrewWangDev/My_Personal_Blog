import type { APIRoute } from 'astro';
import { env } from "cloudflare:workers";

export const POST: APIRoute = async ({ cookies, locals, request }) => {
  const origin = request.headers.get('origin');
  const expectedOrigin = new URL(request.url).origin;
  const fetchSite = request.headers.get('sec-fetch-site');

  if (origin && origin !== expectedOrigin) {
    return new Response(JSON.stringify({ error: 'Forbidden cross-origin request' }), { status: 403 });
  }
  if (!origin && fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    return new Response(JSON.stringify({ error: 'Forbidden cross-site request' }), { status: 403 });
  }

  const user = locals.user;
  if (!user?.id) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  const db = (env as any).DB;
  if (!db) {
    return new Response(JSON.stringify({ error: 'Database unavailable' }), { status: 500 });
  }

  try {
    // 递增 token_version 以彻底使全网/全设备当前有效会话在下一次请求时全部失效
    await db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?')
      .bind(user.id)
      .run();

    // 清空本地当前会话与状态 Cookie
    cookies.delete('user_session', { path: '/' });
    cookies.delete('passkey_reg_ch', { path: '/' });
    cookies.delete('passkey_auth_ch', { path: '/' });
    cookies.delete('passkey_auth_session', { path: '/' });

    return new Response(JSON.stringify({
      success: true,
      message: '全网会话已彻底吊销，请重新登录'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err: any) {
    console.error('Revoke all sessions error:', err);
    return new Response(JSON.stringify({ error: '服务器内部错误，请稍后重试' }), { status: 500 });
  }
};
