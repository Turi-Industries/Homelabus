import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import { settle } from './settle.ts';
import { said } from './words.ts';

/** Every card the home can pin, read from the controller's document. */
function homeWidgets(): string[] {
	const document = JSON.parse(readFileSync('openapi.json', 'utf8')) as {
		components: { schemas: { HomeWidget: { enum: string[] } } };
	};
	return document.components.schemas.HomeWidget.enum;
}

test.describe('the wall display', () => {
	test('offers nothing to click into, by mouse or by keyboard', async ({ page }) => {
		// 🔴 A wall is seen, and touched, by anyone in the room: one link on it and the
		// console opens with the wall's session. Blocking the pointer alone leaves Tab
		// and Enter.
		await page.goto('/kiosk');
		await settle(page);
		await expect(page.getByRole('navigation')).toHaveCount(0);

		for (let press = 0; press < 5; press++) {
			await page.keyboard.press('Tab');
			const focused = await page.evaluate(() => {
				const el = document.activeElement;
				return el === null || el === document.body ? null : el.outerHTML.slice(0, 120);
			});
			expect(focused, 'something on the wall took the focus').toBeNull();
		}
	});

	test('is an allowlist: some cards, never all, never people or secrets', async ({ page }, info) => {
		test.skip(info.project.name !== 'populated', 'with nothing installed, the cards say so the same way');
		const read: string[] = [];
		page.on('request', (r) => read.push(new URL(r.url()).pathname));
		await page.goto('/kiosk');
		await settle(page);

		// A card added to the home tomorrow is not on the wall until someone puts it
		// there: were the wall to show every card, it would have become a denylist.
		const cards = await page.locator('main section').count();
		expect(cards, 'the test above held nothing').toBeGreaterThan(0);
		expect(cards).toBeLessThan(homeWidgets().length);

		// Even unnamed on screen, a list of accounts or secret names is a map of the
		// house, and the audit says who did what to whom.
		const sensitive = read.filter((p) => /^\/api\/(accounts|secrets|audit|invitations)\b/.test(p));
		expect(sensitive).toEqual([]);
	});
});

test('a URL no page answers says so, with the way home', async ({ page }) => {
	const errors: string[] = [];
	page.on('pageerror', (e) => errors.push(e.message));
	await page.goto('/nowhere-at-all');
	await expect(page.getByText(said('state_not_found'))).toBeVisible();
	await expect(page.getByRole('link', { name: said('state_go_home') })).toHaveAttribute('href', '/');
	await expect(page).toHaveTitle(said('state_not_found'));
	expect(errors).toEqual([]);
});
