import { marked } from 'marked';
import xss from 'xss';
import { isSafeUrl } from './validation';

const xssLib = xss as any;
const getDefaultWhiteList = xssLib.getDefaultWhiteList || xssLib.default?.getDefaultWhiteList;
const safeAttrValue = xssLib.safeAttrValue || xssLib.default?.safeAttrValue;

const customWhiteList = {
  ...(typeof getDefaultWhiteList === 'function' ? getDefaultWhiteList() : {}),
  code: ['class'],
  pre: ['class'],
  span: ['class'],
  h1: ['id'],
  h2: ['id'],
  h3: ['id'],
  h4: ['id'],
  h5: ['id'],
  h6: ['id'],
  input: ['type', 'checked', 'disabled'],
  a: ['href', 'title', 'target', 'rel'],
  img: ['src', 'alt', 'title', 'width', 'height'],
};

const xssOptions = {
  whiteList: customWhiteList,
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed'],
  onTagAttr(tag: string, name: string, value: string, isWhiteAttr: boolean) {
    if (!isWhiteAttr) return undefined;
    if ((tag === 'a' && name === 'href') || (tag === 'img' && name === 'src')) {
      const trimmed = value.trim();
      if (trimmed.startsWith('#') && tag === 'a') {
        return `href="${safeAttrValue(tag, name, trimmed, xss.cssFilter)}"`;
      }
      const safe = isSafeUrl(trimmed);
      if (!safe) return '';
      return `${name}="${safeAttrValue(tag, name, safe, xss.cssFilter)}"`;
    }
    if (tag === 'input' && name === 'type') {
      return value === 'checkbox' ? 'type="checkbox"' : '';
    }
    return undefined;
  },
};

export async function renderSafeMarkdown(markdownText: string): Promise<string> {
  if (!markdownText) return '';
  const rawHtml = await marked.parse(markdownText);
  return xss(rawHtml, xssOptions);
}
