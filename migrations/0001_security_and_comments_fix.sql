-- D1 安全与评论一致性迁移脚本
-- 执行前建议先检查是否存在仅大小写不同的重复邮箱：
-- SELECT LOWER(TRIM(email)) AS norm_email, COUNT(*) AS cnt FROM users GROUP BY LOWER(TRIM(email)) HAVING cnt > 1;

-- 1. 统一归一化已有邮箱数据（去首尾空白并转小写）
UPDATE users SET email = LOWER(TRIM(email)) WHERE email != LOWER(TRIM(email));
UPDATE deleted_users SET email = LOWER(TRIM(email)) WHERE email != LOWER(TRIM(email));
UPDATE email_verifications SET email = LOWER(TRIM(email)) WHERE email != LOWER(TRIM(email));
UPDATE email_logs SET email = LOWER(TRIM(email)) WHERE email != LOWER(TRIM(email));
UPDATE user_oauth_accounts SET provider_email = LOWER(TRIM(provider_email)) WHERE provider_email != LOWER(TRIM(provider_email));

-- 2. 重建 comments 表，使 user_id 允许为 NULL 且外键支持 ON DELETE SET NULL
PRAGMA foreign_keys = OFF;

CREATE TABLE IF NOT EXISTS comments_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id TEXT NOT NULL,
    user_id TEXT,
    parent_id INTEGER,
    content TEXT NOT NULL,
    is_deleted INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

INSERT INTO comments_new (id, post_id, user_id, parent_id, content, is_deleted, created_at)
SELECT
    c.id,
    c.post_id,
    CASE WHEN EXISTS (SELECT 1 FROM users u WHERE u.id = c.user_id) THEN c.user_id ELSE NULL END,
    c.parent_id,
    c.content,
    c.is_deleted,
    c.created_at
FROM comments c;

DROP TABLE comments;
ALTER TABLE comments_new RENAME TO comments;
CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);

PRAGMA foreign_keys = ON;

-- 3. 创建 WebAuthn 一次性挑战存储表
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id TEXT PRIMARY KEY,
    challenge TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
