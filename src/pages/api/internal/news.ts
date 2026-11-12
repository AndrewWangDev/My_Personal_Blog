import type { APIRoute } from 'astro';
import { env } from "cloudflare:workers";
import { timingSafeEqualStr } from "../../../utils/password";
import { isSafeUrl } from "../../../utils/validation";

export const POST: APIRoute = async ({ request }) => {
  try {
    // 1. Verify Secret Token
    const authHeader = request.headers.get('Authorization') || '';
    const customHeader = request.headers.get('x-cron-secret') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    const providedSecret = bearerToken || customHeader;
    const expectedSecret = (env as any)?.CRON_SECRET;

    if (!expectedSecret) {
      return new Response(JSON.stringify({ error: "服务器内部定时任务密钥未配置" }), { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!providedSecret || !timingSafeEqualStr(providedSecret, expectedSecret)) {
      return new Response(JSON.stringify({ error: "Unauthorized: Invalid secret key" }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 2. Parse payload
    const data = await request.json();
    const { title, author, thumbnail_url, cover_url, content } = data;

    if (!title || typeof title !== 'string' || !content || typeof content !== 'string' || !title.trim() || !content.trim()) {
      return new Response(JSON.stringify({ error: "Missing required fields: title and content are mandatory" }), { 
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const trimmedTitle = title.trim();
    const trimmedContent = content.trim();
    if (trimmedTitle.length > 200 || trimmedContent.length > 100000) {
      return new Response(JSON.stringify({ error: "Payload field length exceeds allowed limits" }), { 
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (thumbnail_url && !isSafeUrl(thumbnail_url)) {
      return new Response(JSON.stringify({ error: "Invalid thumbnail_url scheme" }), { 
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    if (cover_url && !isSafeUrl(cover_url)) {
      return new Response(JSON.stringify({ error: "Invalid cover_url scheme" }), { 
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const db = (env as any)?.DB;
    if (!db) {
      return new Response(JSON.stringify({ error: "Database connection unavailable" }), { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 3. Check for existing news to ensure idempotency
    const existing = await db.prepare('SELECT id FROM news WHERE title = ? LIMIT 1').bind(trimmedTitle).first();
    if (existing) {
      return new Response(JSON.stringify({ 
        success: true, 
        message: "News with this title already exists. Skipped.",
        skipped: true,
        id: existing.id
      }), { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 4. Insert news into D1
    const finalAuthor = typeof author === 'string' && author.trim() ? author.trim().substring(0, 100) : 'Andrew Wang Dev';
    const finalThumbnail = thumbnail_url ? String(thumbnail_url).trim() : null;
    const finalCover = cover_url ? String(cover_url).trim() : finalThumbnail;

    const result = await db.prepare(`
      INSERT INTO news (title, author, thumbnail_url, cover_url, content)
      VALUES (?, ?, ?, ?, ?)
    `).bind(
      trimmedTitle,
      finalAuthor,
      finalThumbnail,
      finalCover,
      trimmedContent
    ).run();

    if (result.success) {
      return new Response(JSON.stringify({ 
        success: true, 
        message: "News published successfully", 
        id: result.meta?.last_row_id || null 
      }), { 
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({ error: "Failed to insert news into database" }), { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error: any) {
    console.error("Error in internal news ingestion API:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), { 
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};
