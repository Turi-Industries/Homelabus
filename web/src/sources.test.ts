import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/** Every hand-written source under `src/`: walked, never listed. */
function sources(dir = 'src'): string[] {
	return readdirSync(dir).flatMap((name) => {
		const path = join(dir, name);
		// Generated from `messages/` and `openapi.json`: neither is written here.
		if (path === join('src', 'lib', 'paraglide') || name.endsWith('.d.ts')) return [];
		if (statSync(path).isDirectory()) return sources(path);
		return /\.(svelte|ts|js|css|html)$/.test(name) ? [path] : [];
	});
}

/**
 * Tailwind's stock colour names, read from the stylesheet the installed Tailwind ships —
 * so a palette a release adds is refused without anyone updating this test.
 */
function stockColours(): string[] {
	const theme = readFileSync('node_modules/tailwindcss/theme.css', 'utf8');
	const names = [...theme.matchAll(/--color-([a-z]+)(?:-\d+)?:/g)].map((x) => x[1] ?? '');
	return [...new Set(names)];
}

/** What, in `text`, is a colour no theme controls. */
export function literalColours(text: string, stock: string[]): string[] {
	const patterns = [
		// `#0F1216`, `#fff` — but not `#lib/…`, whose letters are not all hexadecimal.
		/#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})(?![\w-])/g,
		/\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\(/g,
		// `text-red-500`, `bg-white`, `border-slate-200/50`.
		new RegExp(`(?<![\\w-])[a-z][a-z-]*-(?:${stock.join('|')})(?:-\\d{2,3})?(?:/\\d+)?(?![\\w-])`, 'g')
	];
	return patterns.flatMap((p) => [...text.matchAll(p)].map((x) => x[0]));
}

describe('the sources', () => {
	const files = sources();
	const stock = stockColours();

	it('are all walked', () => {
		// The floor under the scans below: a walk that silently finds nothing passes them.
		expect(files).toContain(join('src', 'app.css'));
		expect(files).toContain(join('src', 'routes', '+layout.svelte'));
		expect(stock).toEqual(expect.arrayContaining(['red', 'slate', 'white', 'black']));
	});

	it('recognise a literal colour in each of its shapes', () => {
		// The scan below proves nothing unless its patterns match what they are meant to.
		for (const bad of [
			'color: #0F1216;',
			'fill="#fff"',
			'background: rgb(10 20 30)',
			'oklch(0.7 0.1 200)',
			'class="text-red-500"',
			'class="bg-white p-4"',
			'hover:border-slate-200/50'
		]) {
			expect(literalColours(bad, stock), bad).not.toEqual([]);
		}
		for (const fine of [
			"import { api } from '#lib/api/client.ts';",
			'class="bg-surface text-critical"',
			'whitespace-nowrap',
			'--color-text: CanvasText;'
		]) {
			expect(literalColours(fine, stock), fine).toEqual([]);
		}
	});

	it('write no colour by hand', () => {
		// 🔴 A hex value or a stock colour is one no theme — and no palette check —
		// controls: the separation the server validates for colour-blind readers stops
		// applying the moment one is written. Use a palette role: `text-critical`.
		// The tests are left out: they ship nothing, and this one spells what it refuses.
		const found = files
			.filter((f) => !f.endsWith('.test.ts'))
			.flatMap((f) =>
			literalColours(readFileSync(f, 'utf8'), stock).map((c) => `${f}: ${c}`)
		);
		expect(found).toEqual([]);
	});

	it('reach the API through the generated client only', () => {
		// 🔴 A bare `fetch` sends no `x-hlb-ui`, so the controller refuses it as a forged
		// request the moment it mutates — and nothing checks its path or body against
		// the document.
		const client = join('src', 'lib', 'api', 'client.ts');
		const bare = files
			.filter((f) => f !== client && !f.endsWith('.test.ts'))
			.filter((f) => /\bfetch\(|XMLHttpRequest|EventSource/.test(readFileSync(f, 'utf8')));
		expect(bare).toEqual([]);
	});
});
