import fs from 'node:fs';
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import cloudflare from '@astrojs/cloudflare';

// CI / 脱敏环境容错：若本地无 wrangler.json 则自动回退到合规扩展名的 wrangler.example.json 模板
const wranglerConfigPath = fs.existsSync('wrangler.json') ? 'wrangler.json' : 'wrangler.example.json';

export default defineConfig({
  vite: {
    plugins: [tailwindcss()],
  },
  output: 'server',
  adapter: cloudflare({
    configPath: wranglerConfigPath,
  }),
  site: 'https://andrewwangdev.com',
  redirects: {
    '/blog/': '/',
    '/index.html': '/'
  }
});