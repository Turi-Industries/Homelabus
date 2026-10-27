import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';
import { controller, EMPTY, LARGE, POPULATED, SCREENS } from './e2e/controller.ts';

// One directory for the whole run: the config is loaded again in every worker, and the
// environment is what they inherit from the process that started them.
process.env.HLB_E2E_DIR ??= mkdtempSync(join(tmpdir(), 'hlb-e2e-'));
const dir = process.env.HLB_E2E_DIR;
const OWN = /staleness\.spec\.ts/;
const SCALE = /scale\.spec\.ts/;
// Beside a walk of every page, these spend the read budget it needs and turn it into
// 429s — the home alone reads 22 routes and icons. They have a controller of their own,
// the demonstration at scale, whose home has the most to fit on one screen.
const MODALS = /modals\.spec\.ts/;
const HOME = /home\.spec\.ts/;

/**
 * The interface against real controllers, never against stubbed answers: a stub is a
 * second definition of the API, and the one place it differs is the one place the
 * test would be wrong. `populated` is the demonstration data; `empty` is a fresh
 * installation, the state nobody looks at while developing; `large` is the
 * demonstration at a thousand accounts, which the household's four cannot stand for.
 */
export default defineConfig({
	testDir: 'e2e',
	// The controller's per-address budget is 600 reads a minute, and every worker reads
	// from 127.0.0.1: more workers than this spend it and turn a pass into a 429.
	workers: 2,
	forbidOnly: !!process.env.CI,
	reporter: process.env.CI ? 'github' : 'list',
	use: { ...devices['Desktop Chrome'], trace: 'retain-on-failure' },
	projects: [
		{ name: 'populated', use: { baseURL: `http://${POPULATED}` }, testIgnore: [OWN, SCALE, MODALS, HOME] },
		// The empty home is checked too: with nothing to list, it must still fill the screen.
		{ name: 'empty', use: { baseURL: `http://${EMPTY}` }, testIgnore: [OWN, SCALE, MODALS] },
		{ name: 'large', use: { baseURL: `http://${LARGE}` }, testMatch: SCALE },
		{ name: 'screens', use: { baseURL: `http://${SCREENS}` }, testMatch: [MODALS, HOME] },
		// Tests that start, kill and restart a controller of their own.
		{ name: 'own controller', testMatch: OWN }
	],
	webServer: [
		{ ...controller(POPULATED, ['--demo']), url: `http://${POPULATED}/api/themes` },
		{ ...controller(EMPTY, ['--state', join(dir, 'state.db')]), url: `http://${EMPTY}/api/themes` },
		{ ...controller(LARGE, ['--demo', '--demo-scale', 'large']), url: `http://${LARGE}/api/themes` },
		{ ...controller(SCREENS, ['--demo', '--demo-scale', 'large']), url: `http://${SCREENS}/api/themes` }
	]
});
