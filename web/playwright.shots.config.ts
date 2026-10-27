import { defineConfig } from '@playwright/test';
import base from './playwright.config.ts';

/**
 * The contact sheet (`e2e/shots.ts`), against the browser suite's three controllers —
 * same ports, so the two cannot run at once. `bun run shots`.
 *
 * ⚠️ Behind a `--trusted-proxy`: one person spends the 600-reads-a-minute budget in
 * about one theme and language, so each combination is shown to a different person,
 * named by `X-Forwarded-For` as Caddy would.
 */
export default defineConfig({
	...base,
	testMatch: 'shots.ts',
	globalSetup: './e2e/sheet.ts',
	reporter: 'list',
	webServer: [base.webServer ?? []].flat().map((s) => ({ ...s, command: `${s.command} --trusted-proxy` })),
	projects: (base.projects ?? []).filter((p) => p.name !== 'own controller').map(({ name, use }) => ({ name, use }))
});
