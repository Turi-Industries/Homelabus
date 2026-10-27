import type { Page } from '@playwright/test';

/**
 * Until the page is drawn and nothing on it is still loading.
 *
 * ⚠️ "Nothing busy" alone passes on an empty document: SvelteKit draws after the
 * `load` event `goto` waits for. Every page, the error page included, has a `<main>`.
 */
export async function settle(page: Page) {
	await page.waitForFunction(
		() => document.querySelector('main') !== null && document.querySelector('[aria-busy="true"]') === null,
		null,
		{ timeout: 15_000 }
	);
}
