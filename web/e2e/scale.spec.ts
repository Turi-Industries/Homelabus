import { expect, test } from '@playwright/test';
import { patterns } from './routes.ts';
import { patternOf, screens, visit, WIDE } from './walk.ts';

/**
 * The demonstration at a thousand accounts (`--demo-scale large`): no page may grow
 * with what it lists. The household's four accounts read fine as cards; at a thousand
 * they were 174 screens, and nothing else in the suite could have said so.
 */

/** Five screens at 1280 × 800: a page, not a list someone scrolls to the end of. */
const TALLEST = 4_000;

test('no page grows with what it lists', async ({ page }) => {
	test.setTimeout(300_000);
	await page.setViewportSize(WIDE);
	const found = await screens(page, true);

	// 🔴 The floor: a walk that reached nothing would find every page short.
	const reached = new Set([...found.values()].map((url) => patternOf(url)?.id));
	expect(patterns().filter((p) => !reached.has(p.id)).map((p) => p.id)).toEqual([]);

	const tall: string[] = [];
	for (const url of found.values()) {
		await visit(page, url);
		const height = await page.evaluate(() => document.documentElement.scrollHeight);
		if (height > TALLEST) tall.push(`${url}: ${height} px`);
	}
	expect(tall).toEqual([]);
});
