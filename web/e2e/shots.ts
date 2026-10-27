import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import type { Schemas } from '../src/lib/api/client.ts';
import { locales, localStorageKey } from '../src/lib/paraglide/runtime.js';
import { patterns } from './routes.ts';
import { OUT, type Run, type Shot } from './sheet.ts';
import { settle } from './settle.ts';
import { NARROW, patternOf, screens, visit, WIDE } from './walk.ts';

/**
 * The contact sheet: every screen, in every theme, language and width, photographed
 * and laid out on one page — `target/shots/index.html`, built by `sheet.ts`.
 *
 * 🔴 Nothing is compared, and a picture can never fail this. It exists so that LOOKING
 * is cheap: every purely visual defect this project has had was found by someone
 * looking at a screenshot, never by diffing two. What does fail it is a sheet with a
 * hole in it — a screen no link reached, or one that could not be drawn.
 *
 * Not a `.spec.ts`, so `bun run test:browser` leaves it alone: `bun run shots` runs it,
 * through `playwright.shots.config.ts`, against the same controllers.
 */

const WIDTHS = { wide: WIDE, narrow: NARROW } satisfies Record<Shot['width'], typeof WIDE>;
type Theme = Schemas['Theme'];

/**
 * Paints the shell in `theme`. The choice is the one value the sheet varies, so it is
 * the one answer altered: the person's preference and the installation's default both
 * name it, whichever the shell reads first. Everything else on screen is the
 * controller's real answer.
 */
async function wear(context: BrowserContext, theme: string, home: { cards: boolean }) {
	await context.route('**/api/preferences', async (route) => {
		const response = await route.fetch();
		if (!response.ok()) return route.fulfill({ response });
		const answer = (await response.json()) as { home_offered: unknown[] };
		// Every card the controller offers, at the size each is added at.
		const cards = home.cards ? { home: answer.home_offered } : {};
		route.fulfill({ response, json: { ...answer, theme, ...cards } });
	});
	await context.route('**/api/appearance', async (route) => {
		const response = await route.fetch();
		if (!response.ok()) return route.fulfill({ response });
		route.fulfill({ response, json: { ...(await response.json()), default_theme: theme } });
	});
}

/**
 * The home again, with every card pinned — last, since reaching it reloads the shell.
 * The default shows six: without this screen the sheet would never show the others.
 */
const PINNED = 'home+cards';

/** A name as a file name: no space, no slash. */
function slug(name: string): string {
	return name === '/' ? 'home' : name.replace(/^\//, '').replace(/[^\w-]+/g, '_');
}

/**
 * The page at `width`, as a screen tall enough to hold all of it would show it.
 *
 * ⚠️ Not `fullPage`: that stitches the document under a viewport that stays its
 * height, so the navigation — `sticky`, `h-dvh` — ends 800 px down on a long page, a
 * defect no person ever sees.
 */
async function photograph(tab: Page, width: typeof WIDE, path: string): Promise<number> {
	await tab.setViewportSize(width);
	const height = await tab.evaluate(() => document.documentElement.scrollHeight);
	// ⚠️ Capped: a thousand accounts as cards is a page no browser surface holds. The
	// height is still RETURNED whole — how many screens a page costs is the measurement.
	await tab.setViewportSize({ width: width.width, height: Math.min(TALLEST, Math.max(width.height, height)) });
	await tab.screenshot({ path, animations: 'disabled', caret: 'hide' });
	return height;
}

/** The tallest picture taken, in pixels: Chromium refuses a larger surface. */
const TALLEST = 16_000;

test('the contact sheet', async ({ browser, page, request }, info) => {
	test.setTimeout(1_800_000);
	const data = info.project.name;
	const problems: string[] = [];
	const themes = ((await (await request.get('/api/themes')).json()) as Theme[]).map((t) => t.name);

	const found = await screens(page, data !== 'empty');

	// 🔴 The floor: a sheet missing a screen looks complete — nobody counts thumbnails.
	const reached = new Set([...found.values()].map((url) => patternOf(url)?.id));
	const missing = patterns().filter((p) => !reached.has(p.id)).map((p) => p.id);
	expect(missing, 'pages no link and no address reached').toEqual([]);

	const run: Run = { data, themes, locales: [...locales], screens: [] };
	for (const [screen, url] of found) run.screens.push({ screen, url, shots: [] });
	run.screens.push({ screen: PINNED, url: '/', shots: [] });

	let person = 0;
	for (const theme of themes) {
		for (const locale of locales) {
			// Another person for each combination — see `playwright.shots.config.ts`.
			const context = await browser.newContext({
				baseURL: info.project.use.baseURL,
				viewport: WIDE,
				extraHTTPHeaders: { 'x-forwarded-for': `10.0.0.${++person}` }
			});
			await context.addInitScript(({ key, value }) => localStorage.setItem(key, value), {
				key: localStorageKey,
				value: locale
			});
			const home = { cards: false };
			await wear(context, theme, home);
			const tab = await context.newPage();
			let where = '/';
			tab.on('pageerror', (e) => problems.push(`${theme} ${locale} ${where}: threw ${e.message}`));
			// The controller's read budget, spent: the picture would be of the refusal.
			tab.on('response', (r) => {
				if (r.status() === 429) problems.push(`${theme} ${locale} ${where}: 429 from ${new URL(r.url()).pathname}`);
			});
			await tab.goto('/');
			await settle(tab);
			for (const entry of run.screens) {
				where = entry.url;
				if (entry.screen === PINNED) {
					home.cards = true;
					await tab.goto('/');
					// The cards arrive with the preferences, after the shell has settled once.
					await tab.locator('main section > header h2').first().waitFor();
					await settle(tab);
				} else if (entry.url !== '/') await visit(tab, entry.url);
				for (const [width, size] of Object.entries(WIDTHS) as [Shot['width'], typeof WIDE][]) {
					const file = join(data, slug(entry.screen), `${slug(theme)}.${locale}.${width}.png`);
					mkdirSync(join(OUT, data, slug(entry.screen)), { recursive: true });
					const height = await photograph(tab, size, join(OUT, file));
					entry.shots.push({ theme, locale, width, file, screens: Math.round((height / size.height) * 10) / 10 });
				}
				await tab.setViewportSize(WIDE);
			}
			await context.close();
		}
	}

	writeFileSync(join(OUT, `${data}.json`), JSON.stringify(run, null, '\t'));
	console.log(`${data}: ${run.screens.length} screens, ${run.screens.length * themes.length * locales.length * 2} shots`);
	// What a page costs to read, said where the run ends rather than left in a JSON
	// file: the tallest screens, at each width, in the screens they fill.
	for (const width of Object.keys(WIDTHS) as Shot['width'][]) {
		const tallest = run.screens
			.map((s) => ({ screen: s.screen, screens: Math.max(...s.shots.filter((x) => x.width === width).map((x) => x.screens)) }))
			.sort((a, b) => b.screens - a.screens)
			.slice(0, 8);
		console.log(`${data} ${width}, tallest: ${tallest.map((t) => `${t.screen} ${t.screens}`).join(' · ')}`);
	}
	expect(problems).toEqual([]);
});
