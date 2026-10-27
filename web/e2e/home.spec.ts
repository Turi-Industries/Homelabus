import { expect, test } from '@playwright/test';
import { settle } from './settle.ts';
import { NARROW, WIDE } from './walk.ts';
import { said } from './words.ts';

/**
 * The home is read at a glance or not at all: one screen, no scrolling. It was 2.6
 * screens — an inbox of 31 lines in six cards, then four widgets restating it. Its
 * tiles now fill the screen, and a long list scrolls inside its own.
 */

test('the home fits one screen, from a tablet to a wide screen', async ({ page }) => {
	// 🔴 Measured at one size, it fitted at 1280 × 800 and took two screens at 1024: the
	// columns follow the grid's width, which the navigation beside it narrows.
	for (const screen of [WIDE, { width: 1920, height: 1080 }, { width: 1024, height: 768 }, { width: 800, height: 1000 }]) {
		await page.setViewportSize(screen);
		await page.goto('/');
		await settle(page);
		const height = await page.evaluate(() => document.documentElement.scrollHeight);
		expect(height, `the home scrolls at ${screen.width} × ${screen.height}`).toBeLessThanOrEqual(screen.height);
	}
});

test('on a phone, the figures and the first problems are above the fold', async ({ page }, info) => {
	test.skip(info.project.name === 'empty', 'an empty installation has no problem to show');
	await page.setViewportSize(NARROW);
	await page.goto('/');
	await settle(page);
	const figures = page.getByRole('heading', { name: said('widget_summary') });
	const third = page.locator('section[aria-labelledby="inbox-title"] li').nth(2);
	await expect(third).toBeVisible();
	const bottom = await third.evaluate((el) => el.getBoundingClientRect().bottom);
	expect(bottom, 'the third problem is below the fold').toBeLessThanOrEqual(NARROW.height);
	await expect(figures).toBeInViewport();
});
