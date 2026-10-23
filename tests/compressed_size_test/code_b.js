export const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (ch) => ESCAPES[ch]);
}

export function slugify(title) {
  return title
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function renderInline(source) {
  let html = escapeHtml(source);
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  html = html.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, label, href) => {
    const safe = /^(https?:|mailto:|\/|#)/i.test(href) ? href : '#';
    return `<a href="${safe}">${label}</a>`;
  });
  return html;
}

export class Markdown {
  constructor({ headingIds = true, tableClass = 'md-table' } = {}) {
    this.headingIds = headingIds;
    this.tableClass = tableClass;
    this.toc = [];
  }

  heading(line) {
    const match = /^(#{1,6})\s+(.*)$/.exec(line);
    const level = match[1].length;
    const text = match[2].trim();
    const id = slugify(text);
    this.toc.push({ level, text, id });
    const attr = this.headingIds ? ` id="${id}"` : '';
    return `<h${level}${attr}>${renderInline(text)}</h${level}>`;
  }

  table(rows) {
    const cells = (row) => row.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
    const head = cells(rows[0]);
    const align = cells(rows[1]).map((c) =>
      c.startsWith(':') && c.endsWith(':') ? 'center' : c.endsWith(':') ? 'right' : 'left');
    const th = head.map((c, i) => `<th style="text-align:${align[i]}">${renderInline(c)}</th>`);
    const body = rows.slice(2).map((row) => {
      const td = cells(row).map((c, i) => `<td style="text-align:${align[i] || 'left'}">${renderInline(c)}</td>`);
      return `<tr>${td.join('')}</tr>`;
    });
    return `<table class="${this.tableClass}"><thead><tr>${th.join('')}</tr></thead><tbody>${body.join('')}</tbody></table>`;
  }

  list(items, ordered) {
    const tag = ordered ? 'ol' : 'ul';
    const li = items.map((item) => `<li>${renderInline(item.replace(/^\s*([-*+]|\d+\.)\s+/, ''))}</li>`);
    return `<${tag}>${li.join('')}</${tag}>`;
  }

  render(markdown) {
    const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
    const out = [];
    let i = 0;
    this.toc = [];
    while (i < lines.length) {
      const line = lines[i];
      if (/^```/.test(line)) {
        const lang = line.slice(3).trim();
        const code = [];
        i++;
        while (i < lines.length && !/^```/.test(lines[i])) {
          code.push(escapeHtml(lines[i]));
          i++;
        }
        i++;
        const cls = lang ? ` class="language-${lang}"` : '';
        out.push(`<pre><code${cls}>${code.join('\n')}</code></pre>`);
      } else if (/^#{1,6}\s/.test(line)) {
        out.push(this.heading(line));
        i++;
      } else if (/^\|.*\|\s*$/.test(line) && /^\|?\s*:?-{3,}/.test(lines[i + 1] || '')) {
        const rows = [];
        while (i < lines.length && /^\|.*\|\s*$/.test(lines[i])) {
          rows.push(lines[i]);
          i++;
        }
        out.push(this.table(rows));
      } else if (/^\s*([-*+]|\d+\.)\s+/.test(line)) {
        const ordered = /^\s*\d+\./.test(line);
        const items = [];
        while (i < lines.length && /^\s*([-*+]|\d+\.)\s+/.test(lines[i])) {
          items.push(lines[i]);
          i++;
        }
        out.push(this.list(items, ordered));
      } else if (/^>\s?/.test(line)) {
        const quote = [];
        while (i < lines.length && /^>\s?/.test(lines[i])) {
          quote.push(lines[i].replace(/^>\s?/, ''));
          i++;
        }
        out.push(`<blockquote>${this.render(quote.join('\n'))}</blockquote>`);
      } else if (line.trim() === '') {
        i++;
      } else {
        const para = [];
        while (i < lines.length && lines[i].trim() !== '' && !/^(#{1,6}\s|```|>|\s*([-*+]|\d+\.)\s)/.test(lines[i])) {
          para.push(lines[i].trim());
          i++;
        }
        out.push(`<p>${renderInline(para.join(' '))}</p>`);
      }
    }
    return out.join('\n');
  }

  tableOfContents() {
    const items = this.toc.map((h) => `${'  '.repeat(h.level - 1)}- [${h.text}](#${h.id})`);
    return items.join('\n');
  }
}

export function wordCount(markdown) {
  const text = markdown.replace(/```[\s\S]*?```/g, ' ').replace(/[#>*_`|\-[\]()]/g, ' ');
  const words = text.split(/\s+/).filter(Boolean);
  return { words: words.length, minutes: Math.max(1, Math.round(words.length / 200)) };
}

export default function renderMarkdown(markdown, options) {
  const md = new Markdown(options);
  const html = md.render(markdown);
  return { html, toc: md.tableOfContents(), stats: wordCount(markdown) };
}
