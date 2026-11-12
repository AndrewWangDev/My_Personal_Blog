import type { APIRoute } from 'astro';
import { env } from "cloudflare:workers";

export const PUT: APIRoute = async ({ request, locals }) => {
  if (!locals.user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  try {
    const data = await request.json();
    const { age, bio } = data;

    // 基础验证
    const ageStr = age !== undefined && age !== null ? String(age).trim() : '';
    let validAge: string | null = null;
    if (ageStr !== '') {
      if (!/^\d{1,3}$/.test(ageStr)) {
        return new Response(JSON.stringify({ error: '年龄不合法' }), { status: 400 });
      }
      const ageNum = Number(ageStr);
      if (!Number.isInteger(ageNum) || ageNum < 0 || ageNum > 150) {
        return new Response(JSON.stringify({ error: '年龄不合法' }), { status: 400 });
      }
      validAge = String(ageNum);
    }

    const safeBio = typeof bio === 'string' ? bio.trim().substring(0, 500) : '';

    const db = env.DB;
    if (!db) {
      throw new Error("DB not found");
    }

    await db.prepare('UPDATE users SET age = ?, bio = ? WHERE id = ?')
      .bind(validAge, safeBio, locals.user.id)
      .run();

    return new Response(JSON.stringify({ success: true, message: '个人信息已更新' }), { status: 200 });
  } catch (err: any) {
    console.error('Update profile error:', err);
    return new Response(JSON.stringify({ error: '服务器内部错误' }), { status: 500 });
  }
};
