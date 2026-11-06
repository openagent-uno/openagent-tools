import { chromium, firefox, webkit, Browser } from 'playwright';
import { resolveChromiumExecutable } from './browser-executable.js';

export class BrowserPool {
  private browsers: Map<string, Browser> = new Map();
  private launches: Map<string, Promise<Browser>> = new Map();
  private closing: Promise<void> | null = null;
  private maxBrowsers: number;
  private browserTypes: string[];
  private currentBrowserIndex = 0;
  private headless: boolean;
  private lastUsedBrowserType: string = '';

  constructor() {
    // Read configuration from environment variables
    this.maxBrowsers = parseInt(process.env.MAX_BROWSERS || '3', 10);
    this.headless = process.env.BROWSER_HEADLESS !== 'false'; // Default to true
    
    // Configure browser types based on environment
    const browserTypesEnv = process.env.BROWSER_TYPES || 'chromium';
    this.browserTypes = browserTypesEnv.split(',').map(type => type.trim());
    
    console.log(`[BrowserPool] Configuration: maxBrowsers=${this.maxBrowsers}, headless=${this.headless}, types=${this.browserTypes.join(',')}`);
  }

  async getBrowser(): Promise<Browser> {
    if (this.closing) await this.closing;
    // Rotate between browser types for variety
    const browserType = this.browserTypes[this.currentBrowserIndex % this.browserTypes.length];
    this.currentBrowserIndex++;
    this.lastUsedBrowserType = browserType;

    const pending = this.launches.get(browserType);
    if (pending) return pending;
    const previous = this.browsers.get(browserType);
    if (previous?.isConnected()) return previous;
    // Publish ownership before another acquisition can race the launch. A
    // map entry containing only completed launches loses all but the last
    // browser when a batch reaches this point concurrently.
    const launch = this.launchBrowser(browserType, previous);
    this.launches.set(browserType, launch);
    try {
      return await launch;
    } finally {
      if (this.launches.get(browserType) === launch) this.launches.delete(browserType);
    }
  }

  private async launchBrowser(browserType: string, previous?: Browser): Promise<Browser> {
    if (previous) {
      this.browsers.delete(browserType);
      await previous.close().catch(error => console.error('Error closing disconnected browser:', error));
    }
    // Launch new browser
    console.log(`[BrowserPool] Launching new ${browserType} browser`);
    
    const launchOptions = {
      headless: this.headless,
      args: [
        '--no-sandbox',
        '--disable-blink-features=AutomationControlled',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-default-apps',
        '--disable-extensions',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-features=TranslateUI',
        '--disable-ipc-flooding-protection',
      ],
    };

    let browser: Browser;
    try {
      switch (browserType) {
        case 'chromium':
          {
            const executablePath = resolveChromiumExecutable();
            browser = await chromium.launch({
              ...launchOptions,
              ...(executablePath ? { executablePath } : {}),
            });
          }
          break;
        case 'firefox':
          browser = await firefox.launch(launchOptions);
          break;
        case 'webkit':
          browser = await webkit.launch(launchOptions);
          break;
        default:
          {
            const executablePath = resolveChromiumExecutable();
            browser = await chromium.launch({
              ...launchOptions,
              ...(executablePath ? { executablePath } : {}),
            });
          }
      }

      this.browsers.set(browserType, browser);
      
      // Clean up old browsers if we have too many
      if (this.browsers.size > this.maxBrowsers) {
        const oldestBrowser = this.browsers.entries().next().value;
        if (oldestBrowser) {
          try {
            await oldestBrowser[1].close();
          } catch (error) {
            console.error(`[BrowserPool] Error closing old browser:`, error);
          }
          this.browsers.delete(oldestBrowser[0]);
        }
      }

      return browser;
    } catch (error) {
      console.error(`[BrowserPool] Failed to launch ${browserType} browser:`, error);
      throw error;
    }
  }

  async closeAll(): Promise<void> {
    if (this.closing) return this.closing;
    const closing = (async () => {
      // A launch already belongs to this pool even before Playwright returns.
      await Promise.allSettled([...this.launches.values()]);
      const browsers = new Set(this.browsers.values());
      console.log(`[BrowserPool] Closing ${browsers.size} browsers`);
      await Promise.all([...browsers].map(browser => browser.close().catch(error =>
        console.error('Error closing browser:', error))));
      this.browsers.clear();
    })();
    this.closing = closing;
    try { await closing; } finally { this.closing = null; }
  }

  getLastUsedBrowserType(): string {
    return this.lastUsedBrowserType;
  }
}
