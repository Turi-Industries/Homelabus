import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { patterns, serverPrefixes } from './routes.ts';
import { settle } from './settle.ts';
import { direct, links, NARROW, patternOf, visit, WIDE } from './walk.ts';
import { said } from './words.ts';

/**
 * Every page the interface can reach, opened the way a person reaches it — by
 * following links from the home — against a populated controller and an empty one.
 *
 * 🔴 A page can compile and THROW AT RENDER: an index past the end, a field read on
 * `null`. Nothing says so until the page is opened, and of forty pages the broken one is
 * rarely the one being looked at. The empty installation is the case nobody opens.
 */

const prefixes = serverPrefixes();
const all = patterns();

/**
 * Tab from the top of the page to the end of it: everything a mouse can reach must be
 * reached, and must SHOW it has the focus.
 */
async function keyboard(page: Page): Promise<string[]> {
	const total = await page.evaluate(() => {
		const selector =
			'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';
		const targets = [...document.querySelectorAll<HTMLElement>(selector)].filter(
			(el) => el.checkVisibility({ visibilityProperty: true }) && el.closest('[inert]') === null
		);
		// A radio group is ONE stop: Tab enters it, the arrows move inside it.
		targets.forEach((el, i) => {
			const radio = el instanceof HTMLInputElement && el.type === 'radio' && el.name !== '';
			el.dataset.reach = radio ? `radio:${el.name}` : String(i);
		});
		(document.activeElement as HTMLElement | null)?.blur();
		return targets.length;
	});
	const reached = new Set<string>();
	const problems: string[] = [];
	for (let press = 0; press < total + 5; press++) {
		await page.keyboard.press('Tab');
		const focused = await page.evaluate(() => {
			const el = document.activeElement as HTMLElement | null;
			if (el === null || el === document.body) return null;
			const style = getComputedStyle(el);
			const ring =
				(style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0) || style.boxShadow !== 'none';
			const label = (el.getAttribute('aria-label') ?? el.textContent ?? '').trim().slice(0, 40);
			return { id: el.dataset.reach, ring, what: `<${el.tagName.toLowerCase()}> "${label}"` };
		});
		if (focused === null) break;
		if (focused.id !== undefined && reached.has(focused.id)) break;
		if (focused.id !== undefined) reached.add(focused.id);
		if (!focused.ring) problems.push(`focus not shown on ${focused.what}`);
	}
	const missed = await page.evaluate((seen) => {
		const out = new Map<string, string>();
		for (const el of document.querySelectorAll<HTMLElement>('[data-reach]')) {
			const id = el.dataset.reach ?? '';
			if (!seen.includes(id) && !out.has(id)) {
				out.set(id, `<${el.tagName.toLowerCase()}> "${(el.getAttribute('aria-label') ?? el.textContent ?? '').trim().slice(0, 40)}"`);
			}
		}
		return [...out.values()];
	}, [...reached]);
	return [...problems, ...missed.map((m) => `never reached by Tab: ${m}`)];
}

test('every page renders, reads only, fits a phone, and answers to the keyboard', async ({ page }, info) => {
	test.setTimeout(600_000);
	const populated = info.project.name === 'populated';
	const problems: string[] = [];
	let where = '/';

	page.on('pageerror', (e) => problems.push(`${where}: threw ${e.message}`));
	page.on('console', (msg) => {
		// A refused request is reported by the browser as a console error; the response
		// handler below judges those, by status, where it knows which route answered.
		if (msg.type() === 'error' && !msg.text().startsWith('Failed to load resource')) {
			problems.push(`${where}: console error ${msg.text()}`);
		}
	});
	page.on('request', (r) => {
		// 🔴 Visiting a page must never act: anything but a read is a mutation the person
		// did not ask for.
		if (!['GET', 'HEAD'].includes(r.method())) problems.push(`${where}: ${r.method()} ${new URL(r.url()).pathname}`);
	});
	const refused: { where: string; status: number; path: string }[] = [];
	page.on('response', (r) => {
		if (r.status() >= 400) refused.push({ where, status: r.status(), path: new URL(r.url()).pathname });
	});

	await page.setViewportSize(WIDE);
	await page.goto('/');
	await settle(page);
	const source: string = (await (await page.request.get('/healthz')).json()).source;
	expect(source, 'the source this build names').toMatch(/^https:\/\//);

	const queue = ['/'];
	const seen = new Set(queue);
	const visited: string[] = [];
	const keyboarded = new Set<string>();

	for (const url of direct(populated)) if (!seen.has(url)) (seen.add(url), queue.push(url));

	while (queue.length > 0) {
		const url = queue.shift() as string;
		where = url;
		if (url !== '/') await visit(page, url);
		visited.push(url);

		const pattern = patternOf(url);
		if (pattern === undefined) problems.push(`${url}: no page answers this link`);
		// 🔴 Reached through the router, a page can still fail a RELOAD: the server's
		// fallback once took every name with a dot for a file, and every machine and every
		// `firstname.lastname` answered 404 to a shared link.
		const direct = await page.request.get(url);
		if (!direct.ok() || !(direct.headers()['content-type'] ?? '').startsWith('text/html')) {
			problems.push(`${url}: a reload answers ${direct.status()}`);
		}
		// The AGPL (§13): whoever runs a modified copy for others offers them its source.
		// Not the kiosk: an `inert` wall nobody in the room can follow a link on.
		if (!url.startsWith('/kiosk') && !(await page.locator(`a[href="${source}"]`).first().isVisible())) {
			problems.push(`${url}: no visible link to the source`);
		}
		if (await page.getByText(said('state_not_found')).isVisible()) {
			problems.push(`${url}: leads to "${said('state_not_found').source}"`);
		}
		// A detail naming nothing must say so — a Retry there asks the same question again.
		if (url.includes('nothing-by-that-name')) {
			if (!(await page.getByText(said('state_gone')).isVisible())) problems.push(`${url}: does not say it names nothing`);
			if (await page.getByRole('button', { name: said('state_retry') }).isVisible()) problems.push(`${url}: offers Retry on a 404`);
		}
		for (const next of await links(page)) {
			if (!seen.has(next)) (seen.add(next), queue.push(next));
		}

		const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
		for (const v of axe.violations) {
			problems.push(`${url}: axe ${v.id} ×${v.nodes.length} — ${v.nodes[0]?.target.join(' ')}`);
		}

		// Once per kind of page: the Tab walk is the slow check, and two applications'
		// details differ in data, not in what can be focused.
		if (pattern !== undefined && !keyboarded.has(pattern.id)) {
			keyboarded.add(pattern.id);
			for (const p of await keyboard(page)) problems.push(`${url}: ${p}`);
		}

		await page.setViewportSize(NARROW);
		const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
		if (overflow > 0) problems.push(`${url}: ${overflow}px wider than a ${NARROW.width}px screen`);
		await page.setViewportSize(WIDE);
	}

	for (const r of refused) {
		// With nothing installed, a page naming something that does not exist is told so
		// by the controller — that 404 is the page working.
		const expected = !populated && r.status === 404 && r.where.includes('nothing-by-that-name');
		if (!expected) problems.push(`${r.where}: ${r.status} from ${r.path}`);
	}

	// 🔴 The floor under everything above: a crawl that found nothing would pass it.
	const reached = new Set(visited.map((u) => patternOf(u)?.id));
	const missing = all.filter((p) => !reached.has(p.id)).map((p) => p.id);
	expect(missing, 'pages no link and no address reached').toEqual([]);

	// 🔴 The service worker never caches the API: a cached answer is the green
	// dashboard served while the cluster burns. True today because there is no worker;
	// this keeps it true when one arrives.
	const cached = await page.evaluate(async () => {
		const out: string[] = [];
		for (const name of await caches.keys()) {
			for (const req of await (await caches.open(name)).keys()) out.push(new URL(req.url).pathname);
		}
		return out;
	});
	expect(cached.filter((path) => prefixes.some((p) => path === p || path.startsWith(p + '/')))).toEqual([]);

	console.log(`${info.project.name}: ${visited.length} pages visited`);
	expect(problems).toEqual([]);
});
