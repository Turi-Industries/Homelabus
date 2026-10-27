import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from '@playwright/test';
import { run, start, type Owned } from './controller.ts';
import { said } from './words.ts';

/**
 * Does the interface lie when the controller goes down?
 *
 * 🔴 THE test of the interface. A screen that polls and keeps its last known state
 * shows, once the source is gone, exactly the screen of a healthy system: every app
 * green, the backups recent. At the precise moment it is needed, it reassures wrongly.
 * These start a real controller, kill it, and read what the page says.
 */

// Each test owns its controller on its own port, so killing it disturbs nobody.
const ADDRESS = '127.0.0.1:8433';
const SIGNED_OUT = '127.0.0.1:8434';
// One polling period of `resource.svelte.ts`, and a little more.
const A_TURN = 16_000;

let controller: Owned | undefined;
test.afterEach(async () => {
	await controller?.kill();
	controller = undefined;
});

test('a dead controller makes the page say so, and keeps what it knew', async ({ page }) => {
	controller = await start(ADDRESS, ['--demo']);
	await page.clock.install();
	await page.goto(`http://${ADDRESS}/apps`);
	const known = page.locator('a[href="/apps/gitea"]');
	await expect(known).toBeVisible();
	await expect(page.getByText(said('state_stale'))).toHaveCount(0);

	await controller.kill();
	await page.clock.fastForward(A_TURN);

	// Said on the page, beside the data it dates...
	await expect(page.getByRole('alert').filter({ hasText: said('state_stale') }).first()).toBeVisible();
	// ...and in the shell, whatever page is open.
	await expect(page.getByRole('status').filter({ hasText: said('state_unreachable_short') })).toBeVisible();
	// The last known state is worth showing — marked, never dropped.
	await expect(known).toBeVisible();
});

test('a controller that comes back clears the warning', async ({ page }) => {
	controller = await start(ADDRESS, ['--demo']);
	await page.clock.install();
	await page.goto(`http://${ADDRESS}/apps`);
	await expect(page.locator('a[href="/apps/gitea"]')).toBeVisible();

	await controller.kill();
	await page.clock.fastForward(A_TURN);
	await expect(page.getByText(said('state_stale')).first()).toBeVisible();

	// A restart is a moment, not a verdict.
	controller = await start(ADDRESS, ['--demo']);
	await page.clock.fastForward(A_TURN);
	await expect(page.getByText(said('state_stale'))).toHaveCount(0);
	await expect(page.getByText(said('state_unreachable_short'))).toHaveCount(0);
});

test('signed out, the page says how to sign in', async ({ page }) => {
	// The first run compiles the CLI.
	test.setTimeout(600_000);
	// A controller that requires authentication refuses to start with no token at all:
	// one has to exist, even if nobody here holds it.
	const dir = mkdtempSync(join(run(), 'signed-out-'));
	const state = join(dir, 'state.db');
	execFileSync('cargo', ['run', '-q', '-p', 'hlb-cli', '--', 'token', 'create', 'unused', '--state', state, '--apply'], {
		stdio: 'ignore'
	});
	controller = await start(SIGNED_OUT, ['--state', state, '--master-key', join(dir, 'vault.key')], { open: false });

	await page.goto(`http://${SIGNED_OUT}/apps`);
	await expect(page.getByText(said('state_signed_out'))).toBeVisible();
	const signIn = page.getByRole('link', { name: said('state_sign_in') });
	// Back to the page that was asked for, once signed in.
	await expect(signIn).toHaveAttribute('href', '/auth/signin?return_to=%2Fapps');
	// Nothing of the console is drawn for someone the controller does not know.
	await expect(page.getByRole('navigation')).toHaveCount(0);
});
