import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { isSafeUrl } from "../../../../utils/validation";

export const GET: APIRoute = async ({ locals, request }) => {
  const user = locals.user;
  if (!user || user.role !== 'admin') {
    return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401 });
  }

  const db = env.DB;
  try {
    const { results } = await db.prepare('SELECT * FROM showcase ORDER BY display_order ASC, created_at DESC').all();
    return new Response(JSON.stringify({ success: true, showcase: results || [] }));
  } catch (error: any) {
    console.error("Showcase GET Error:", error);
    return new Response(JSON.stringify({ success: false, error: '获取橱窗列表失败' }), { status: 500 });
  }
};

export const POST: APIRoute = async ({ locals, request }) => {
  const user = locals.user;
  if (!user || user.role !== 'admin') {
    return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401 });
  }

  const { image_url, link_url, display_order } = await request.json();
  if (!image_url || !link_url) {
    return new Response(JSON.stringify({ success: false, error: 'Missing fields' }), { status: 400 });
  }
  if (!isSafeUrl(image_url) || !isSafeUrl(link_url)) {
    return new Response(JSON.stringify({ success: false, error: '仅支持安全的 HTTP/HTTPS 链接' }), { status: 400 });
  }

  const db = env.DB;
  try {
    // 检查是否超过5个
    const { results } = await db.prepare('SELECT COUNT(*) as count FROM showcase').all();
    if (results[0].count >= 5) {
      return new Response(JSON.stringify({ success: false, error: '橱窗最多只能展示5张图' }), { status: 400 });
    }

    await db.prepare('INSERT INTO showcase (image_url, link_url, display_order) VALUES (?, ?, ?)')
      .bind(image_url.trim(), link_url.trim(), display_order || 0)
      .run();
    return new Response(JSON.stringify({ success: true }));
  } catch (error: any) {
    console.error("Showcase POST Error:", error);
    return new Response(JSON.stringify({ success: false, error: '添加橱窗项失败' }), { status: 500 });
  }
};
