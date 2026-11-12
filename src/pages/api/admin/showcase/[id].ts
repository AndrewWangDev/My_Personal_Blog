import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { isSafeUrl } from "../../../../utils/validation";

export const PUT: APIRoute = async ({ locals, request, params }) => {
  const user = locals.user;
  if (!user || user.role !== 'admin') {
    return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401 });
  }

  const { id } = params;
  const { image_url, link_url, display_order } = await request.json();

  if (!isSafeUrl(image_url) || !isSafeUrl(link_url)) {
    return new Response(JSON.stringify({ success: false, error: '仅支持安全的 HTTP/HTTPS 链接' }), { status: 400 });
  }

  const db = env.DB;
  try {
    await db.prepare('UPDATE showcase SET image_url = ?, link_url = ?, display_order = ? WHERE id = ?')
      .bind(image_url.trim(), link_url.trim(), display_order, id)
      .run();
    return new Response(JSON.stringify({ success: true }));
  } catch (error: any) {
    console.error("Showcase PUT Error:", error);
    return new Response(JSON.stringify({ success: false, error: '更新橱窗项失败' }), { status: 500 });
  }
};

export const DELETE: APIRoute = async ({ locals, params }) => {
  const user = locals.user;
  if (!user || user.role !== 'admin') {
    return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401 });
  }

  const { id } = params;
  const db = env.DB;
  try {
    await db.prepare('DELETE FROM showcase WHERE id = ?').bind(id).run();
    return new Response(JSON.stringify({ success: true }));
  } catch (error: any) {
    console.error("Showcase DELETE Error:", error);
    return new Response(JSON.stringify({ success: false, error: '删除橱窗项失败' }), { status: 500 });
  }
};
