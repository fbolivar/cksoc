/**
 * Conversion de HTML a PDF con Puppeteer (Chromium headless).
 * Reutiliza una sola instancia del navegador entre generaciones.
 */
import puppeteer, { type Browser } from 'puppeteer';
import { env } from '../../config/env';

let browser: Browser | null = null;

async function getBrowser(): Promise<Browser> {
  if (browser && browser.connected) return browser;
  browser = await puppeteer.launch({
    headless: true,
    executablePath: env.PUPPETEER_EXECUTABLE_PATH || undefined,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
  });
  return browser;
}

/** Renderiza HTML a un Buffer PDF (A4, con margenes). */
export async function htmlToPdf(html: string): Promise<Buffer> {
  const b = await getBrowser();
  const page = await b.newPage();
  try {
    await page.setContent(html, { waitUntil: 'networkidle0', timeout: 30_000 });
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '0', bottom: '0', left: '0', right: '0' },
    });
    return Buffer.from(pdf);
  } finally {
    await page.close();
  }
}

/** Cierra el navegador (al apagar el proceso). */
export async function closePdfEngine(): Promise<void> {
  if (browser) {
    await browser.close();
    browser = null;
  }
}
