import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { settle } from './settle.ts';
import { said } from './words.ts';

/**
 * What a button opens comes over the page, and goes on Escape. The crawl sees every page
 * with its modals closed, so what is inside one is checked here, opened — against the
 * demonstration at scale, whose controller the crawl does not share.
 *
 * Left out: Bitwarden's, since opening it asks the server for a key, which is the point.
 * The home's "arrange" and "later" are offered to an account only: `--demo` acts for its
 * administrator, so they are here.
 */
const opened = [
	{ page: '/invitations', button: 'people_new_invitation', title: 'people_new_invitation' },
	{ page: '/catalog', button: 'catalog_install', title: 'catalog_install_title' },
	{ page: '/alerts', button: 'alerts_mute', title: 'alerts_mute_title' },
	{ page: '/', button: 'home_arrange', title: 'home_arrange_title' },
	{ page: '/', button: 'inbox_later', title: 'inbox_later_title' }
];

for (const { page: url, button, title } of opened) {
	test(`${url}: "${button}" opens a modal that closes on Escape`, async ({ page }) => {
		const acted: string[] = [];
		page.on('request', (r) => {
			if (!['GET', 'HEAD'].includes(r.method())) acted.push(`${r.method()} ${new URL(r.url()).pathname}`);
		});
		await page.goto(url);
		await settle(page);

		const opener = page.getByRole('button', { name: said(button) }).first();
		await opener.click();
		const dialog = page.getByRole('dialog', { name: said(title) });
		await expect(dialog).toBeVisible();
		await expect(dialog.getByRole('heading', { name: said(title) })).toBeVisible();
		expect(await dialog.evaluate((d) => d.contains(document.activeElement)), 'the focus stays behind the modal').toBe(true);

		const axe = await new AxeBuilder({ page }).include('dialog[open]').withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
		expect(axe.violations.map((v) => `${v.id} — ${v.nodes[0]?.target.join(' ')}`)).toEqual([]);

		await page.keyboard.press('Escape');
		await expect(dialog).toBeHidden();
		await expect(opener).toBeFocused();
		// Opening a form, or a choice, is not choosing.
		expect(acted).toEqual([]);
	});
}

test('a saved plan is previewed again, never applied', async ({ page }) => {
	// A replay is the request as filed, asked with `apply=false`: what it describes may
	// have changed, so the panel's three beats are owed again.
	const acted: string[] = [];
	page.on('request', (r) => {
		const u = new URL(r.url());
		if (!['GET', 'HEAD'].includes(r.method())) acted.push(`${r.method()} ${u.pathname}${u.search}`);
	});
	await page.goto('/plans');
	await settle(page);

	await page.getByRole('button', { name: said('plans_preview_again') }).first().click();
	const panel = page.getByRole('dialog', { name: said('action_panel_label') });
	await expect(panel.getByText(said('action_preview_nothing_changed_yet'))).toBeVisible();
	expect(acted).toEqual(['POST /api/apps/vikunja/upgrade?apply=false']);
	await page.keyboard.press('Escape');
	await expect(panel).toBeHidden();
});

test('the shortcuts overlay goes on the Escape it lists', async ({ page }) => {
	await page.goto('/');
	await settle(page);
	await page.keyboard.press('?');
	const overlay = page.getByRole('dialog', { name: said('shortcuts_title') });
	await expect(overlay).toBeVisible();
	await page.keyboard.press('Escape');
	await expect(overlay).toBeHidden();
});

test('a copy button without a clipboard selects the text and says so', async ({ page }) => {
	// What a controller reached over plain HTTP by its LAN address offers: no clipboard.
	await page.addInitScript(() => Object.defineProperty(Navigator.prototype, 'clipboard', { get: () => undefined }));
	const thrown: string[] = [];
	page.on('pageerror', (e) => thrown.push(e.message));
	await page.goto('/storage');
	await settle(page);
	await page.getByRole('button', { name: said('storage_wizard_copy') }).first().click();
	await expect(page.getByRole('button', { name: said('action_copy_selected') })).toBeVisible();
	expect(await page.evaluate(() => getSelection()?.toString() ?? '')).toContain('hlb storage init');
	expect(thrown).toEqual([]);
});
