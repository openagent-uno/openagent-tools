import * as cheerio from 'cheerio';
import type { ExtractedPage } from './types.js';

/** Metadata is read before body cleanup; a URL is never a document title. */
export function documentTitle(html: string): string | null {
  const title = cheerio.load(html)('head title').first().text().replace(/\s+/gu, ' ').trim();
  return title ? title.slice(0, 1024) : null;
}

export function formatPageContent(url: string, page: ExtractedPage, maxContentLength?: number): string {
  const { content, title } = page;
  const wordCount = content.split(/\s+/u).filter(Boolean).length;
  let result = `**Page Content from: ${url}**\n\n`;
  result += `**Title:** ${title ?? 'Unavailable (no document title)'}\n`;
  result += `**Word Count:** ${wordCount}\n`;
  result += `**Content Length:** ${content.length} characters\n\n`;
  if (maxContentLength && content.length > maxContentLength) {
    return result + `**Content (truncated at ${maxContentLength} characters):**\n${content.substring(0, maxContentLength)}\n\n[Content truncated at ${maxContentLength} characters]`;
  }
  return result + `**Content:**\n${content}`;
}
