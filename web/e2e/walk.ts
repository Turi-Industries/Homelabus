import type { Page } from '@playwright/test';
import { patterns, serverPrefixes } from './routes.ts';
import { settle } from './settle.ts';

export const WIDE = { width: 1280, height: 800 };
// The narrowest phone in use: where a row that cannot share its line widens the page.
export const NARROW = { width: 360, height: 740 };

const prefixes = serverPrefixes();
const all = patterns();

/** Moves through the SvelteKit router, as a click does — a reload per page would spend
 * the controller's read budget on starting the shell again. */
export async function visit(page: Page, url: string) {
	await page.evaluate((href) => {
		const a = document.createElement('a');
		a.href = href;
		document.body.append(a);
		a.click();
		a.remove();
	}, url);
	await page.waitForURL((u) => u.pathname + u.search === url);
	await settle(page);
}

/** The links on the page that lead to another page of the interface. */
export async function links(page: Page): Promise<string[]> {
	const hrefs = await page.$$eval('a[href]', (as) => as.map((a) => (a as HTMLAnchorElement).href));
	return hrefs.flatMap((href) => {
		const u = new URL(href);
		if (u.origin !== new URL(page.url()).origin) return [];
		if (prefixes.some((p) => u.pathname === p || u.pathname.startsWith(p + '/'))) return [];
		return [u.pathname + u.search];
	});
}

/** What a page is, among the router's patterns. */
export function patternOf(url: string) {
	const path = url.split('?')[0] ?? url;
	return all.find((p) => p.matches.test(path));
}

/**
 * The pages outside the navigation, by address: being unreachable from the shell is
 * what they are for. And with nothing installed, a detail page is reached only by a URL
 * naming something that does not exist — which must render too.
 */
export function direct(populated: boolean): string[] {
	return all
		.filter((p) => !p.shell || (!populated && p.id.includes('[')))
		.map((p) => p.id.replace(/\/\[\[[^\]]+\]\]/g, '').replace(/\[[^\]]+\]/g, 'nothing-by-that-name'));
}

/**
 * The screen a URL shows: which application a detail names is data, which tab it is
 * on is a different screen. So a required parameter collapses, an optional one — the
 * `[[tab]]` — is kept.
 */
function screenOf(url: string): string | undefined {
	const pattern = patternOf(url);
	if (pattern === undefined) return undefined;
	const declared = pattern.id.split('/').filter(Boolean);
	const values = (url.split('?')[0] ?? url).split('/').filter(Boolean);
	const optional = (p: string) => /^\[\[.+\]\]$/.test(p);
	let spare = values.length - declared.filter((p) => !optional(p)).length;
	let at = 0;
	const out: string[] = [];
	for (const part of declared) {
		if (optional(part)) {
			if (spare > 0) (out.push(values[at++] ?? ''), spare--);
		} else {
			out.push(part.startsWith('[') ? part : (values[at] ?? part));
			at++;
		}
	}
	return '/' + out.join('/');
}

/** Every screen, by the first URL found showing it: the crawl's walk, from the home. */
export async function screens(page: Page, populated: boolean): Promise<Map<string, string>> {
	await page.goto('/');
	await settle(page);
	const queue = ['/', ...direct(populated)];
	const seen = new Set(queue);
	const found = new Map<string, string>();
	while (queue.length > 0) {
		const url = queue.shift() as string;
		const screen = screenOf(url);
		if (screen === undefined || found.has(screen)) continue;
		found.set(screen, url);
		await visit(page, url);
		for (const next of await links(page)) if (!seen.has(next)) (seen.add(next), queue.push(next));
	}
	return found;
}
