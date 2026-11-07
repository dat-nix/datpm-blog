import { getCollection } from 'astro:content';

const escapeXml = (value: string) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&apos;');

export async function GET({ site }: { site?: URL }) {
  const posts = (await getCollection('blog', ({ data }) => !data.draft))
    .sort((a, b) => b.data.date.valueOf() - a.data.date.valueOf());
  const origin = site?.toString().replace(/\/$/, '') ?? 'https://datpm.com';
  const items = posts.map(post => {
    const link = `${origin}/writing/${post.id}`;
    return `
      <item>
        <title>${escapeXml(post.data.title)}</title>
        <link>${escapeXml(link)}</link>
        <guid>${escapeXml(link)}</guid>
        <pubDate>${post.data.date.toUTCString()}</pubDate>
        <description>${escapeXml(post.data.excerpt)}</description>
      </item>`;
  }).join('');
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>datpm.com</title>
        <link>${origin}</link>
        <description>Security notes, CTF writeups, and software experiments.</description>
        ${items}
      </channel>
    </rss>`;
  return new Response(xml, { headers: { 'Content-Type': 'application/rss+xml; charset=utf-8' } });
}
