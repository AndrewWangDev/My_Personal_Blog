import type { APIRoute } from 'astro';

export const POST: APIRoute = async ({ request }) => {
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/csp-report') || contentType.includes('application/json')) {
      const report = await request.json().catch(() => null);
      if (report) {
        // 在控制台输出结构化告警日志便于排查潜在误杀或恶意攻击
        console.warn('【CSP Report Triggered】:', JSON.stringify(report));
      }
    }
  } catch (e) {
    // 静默处理，不中断请求
  }

  return new Response(null, { status: 204 });
};
