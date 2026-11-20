import type { APIRoute } from 'astro';
import { env } from "cloudflare:workers";
import { verifyPassword } from '../../../utils/password';
import { normalizeEmail } from '../../../utils/validation';

export const DELETE: APIRoute = async ({ request, cookies, locals }) => {
  if (!locals.user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  // 防御性拦截：禁止管理员账号通过公开个人中心自助注销
  if (locals.user.role === 'admin') {
    return new Response(JSON.stringify({
      error: '管理员账号受系统保护，无法通过自助通道注销，请联系系统运维人员'
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const userId = locals.user.id;

  try {
    const db = env.DB;
    if (!db) {
      throw new Error("DB not found");
    }

    // 1. 获取用户信息以验证密码/身份
    const user = await db.prepare('SELECT id, email, password_hash, auth_provider FROM users WHERE id = ?').bind(userId).first();
    if (!user || !user.email) {
      return new Response(JSON.stringify({ error: '用户不存在' }), { status: 400 });
    }

    // 2. 检查二次认证凭证 (密码或 OAuth 确认标记)
    const body = await request.json().catch(() => ({}));
    const { password, confirmation } = body;

    if (user.password_hash) {
      if (!password) {
        return new Response(JSON.stringify({ error: '请提供当前账号密码以验证注销' }), { status: 400 });
      }
      const { isValid } = await verifyPassword(password, user.password_hash);
      if (!isValid) {
        return new Response(JSON.stringify({ error: '密码错误，无法注销账号' }), { status: 400 });
      }
    } else {
      if (confirmation !== 'DELETE' && confirmation !== user.email) {
        return new Response(JSON.stringify({ error: '第三方登录用户请输入 DELETE 以确认注销' }), { status: 400 });
      }
    }

    const normalizedEmail = normalizeEmail(user.email);

    // 3-6. 原子软删除评论并解除外键引用，硬删除关联记录，写入封禁名单并删除用户
    await db.batch([
      db.prepare('UPDATE comments SET is_deleted = 1, user_id = NULL WHERE user_id = ?').bind(userId),
      db.prepare('DELETE FROM interactions WHERE user_id = ?').bind(userId),
      db.prepare('DELETE FROM user_oauth_accounts WHERE user_id = ?').bind(userId),
      db.prepare('DELETE FROM user_passkeys WHERE user_id = ?').bind(userId),
      db.prepare('UPDATE complaints SET user_id = NULL WHERE user_id = ?').bind(userId),
      db.prepare(`
        INSERT INTO deleted_users (email, expires_at) 
        VALUES (?, datetime('now', '+30 days')) 
        ON CONFLICT(email) DO UPDATE SET expires_at = datetime('now', '+30 days')
      `).bind(normalizedEmail),
      db.prepare('DELETE FROM users WHERE id = ?').bind(userId)
    ]);

    // 7. 清除 Cookie
    cookies.delete('user_session', { path: '/' });

    return new Response(JSON.stringify({ success: true, message: '账号已永久注销' }), { status: 200 });
  } catch (err: any) {
    console.error('Delete account error:', err);
    return new Response(JSON.stringify({ error: '服务器内部错误' }), { status: 500 });
  }
};
