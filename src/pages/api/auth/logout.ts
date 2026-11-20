import type { APIRoute } from 'astro';
import { env } from "cloudflare:workers";

export const POST: APIRoute = async ({ cookies, request }) => {
  const origin = request.headers.get('origin');
  const expectedOrigin = new URL(request.url).origin;
  const fetchSite = request.headers.get('sec-fetch-site');

  if (origin && origin !== expectedOrigin) {
    return new Response(JSON.stringify({ error: 'Forbidden cross-origin logout' }), { status: 403 });
  }
  if (!origin && fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    return new Response(JSON.stringify({ error: 'Forbidden cross-site logout' }), { status: 403 });
  }

  // 1. 若当前会话存在且绑定了 KV，将 Session 哈希加入服务端黑名单（TTL 7 天对齐 Cookie 最大有效期）
  const currentSession = cookies.get('user_session')?.value;
  if (currentSession) {
    const sessionKv = (env as any).SESSION;
    if (sessionKv) {
      try {
        const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(currentSession));
        const hashHex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
        await sessionKv.put(`revoked_session:${hashHex}`, '1', { expirationTtl: 60 * 60 * 24 * 7 });
      } catch (e) {
        console.error('Failed to blacklist session in KV:', e);
      }
    }
  }

  cookies.delete('user_session', { path: '/' });
  cookies.delete('passkey_reg_ch', { path: '/' });
  cookies.delete('passkey_auth_ch', { path: '/' });
  cookies.delete('passkey_auth_session', { path: '/' });
  cookies.delete('oauth_state_google', { path: '/' });
  cookies.delete('oauth_state_github', { path: '/' });
  cookies.delete('github_oauth_state', { path: '/' });
  cookies.delete('github_oauth_action', { path: '/' });

  return new Response(JSON.stringify({
    success: true,
    message: '已成功退出登录'
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
};
