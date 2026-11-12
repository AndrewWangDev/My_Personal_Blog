import type { APIRoute } from 'astro';

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
