// src/utils/validation.ts

export const ALLOWED_EMAIL_DOMAINS = [
  'gmail.com',
  'outlook.com',
  'yahoo.com',
  'hotmail.com',
  'icloud.com',
  'proton.me'
];

export function normalizeEmail(email: unknown): string {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

export function isValidEmailFormat(email: string): boolean {
  if (!email || email.length < 3 || email.length > 254) return false;
  const parts = email.split('@');
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  if (!local || local.length > 64 || !domain || domain.length > 253) return false;
  // Disallow whitespace, quotes, angle brackets, and control chars in local part
  if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) return false;
  if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) return false;
  return true;
}

export function isAllowedEmailDomain(email: string): boolean {
  const normalized = normalizeEmail(email);
  if (!isValidEmailFormat(normalized)) return false;
  const domain = normalized.split('@')[1];
  return ALLOWED_EMAIL_DOMAINS.includes(domain);
}

export function isSafeUrl(url: unknown): string {
  if (typeof url !== 'string') return '';
  const trimmed = url.trim();
  if (!trimmed) return '';
  // 严格相对路径判定：必须以单个 / 开头，且后接字符不得为 / 或 \，且整体不含反斜杠
  if (trimmed === '/' || (/^\/[^/\\]/.test(trimmed) && !trimmed.includes('\\'))) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return trimmed;
    }
  } catch {
    return '';
  }
  return '';
}

export function escapeHtml(str: any): string {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function validateUsername(username: string): { valid: boolean; error?: string } {
  const trimmed = (username || '').trim();
  if (!trimmed || trimmed.length < 2 || trimmed.length > 30) {
    return { valid: false, error: '用户名长度需在 2 到 30 个字符之间' };
  }
  // Allow letters, numbers, Chinese characters, underscores, hyphens
  if (!/^[a-zA-Z0-9_\u4e00-\u9fa5\s-]+$/.test(trimmed)) {
    return { valid: false, error: '用户名仅支持字母、数字、中文、下划线及连字符' };
  }
  return { valid: true };
}
