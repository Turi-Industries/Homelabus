import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

type Catalogue = Record<string, unknown>;

function load(locale: string): Catalogue {
	const { $schema: _, ...messages } = JSON.parse(
		readFileSync(`messages/${locale}.json`, 'utf8')
	) as Catalogue;
	return messages;
}

/** The inputs a message declares, or the `{placeholders}` of a plain one. */
function inputs(message: unknown): string[] {
	if (typeof message === 'string') {
		return [...message.matchAll(/(?<!\\)\{([a-z_0-9]+)\}/g)].map((x) => x[1] ?? '').sort();
	}
	const [variants] = message as [{ declarations: string[] }];
	return variants.declarations
		.filter((d) => d.startsWith('input '))
		.map((d) => d.slice('input '.length))
		.sort();
}

describe('the catalogues', () => {
	const locales = JSON.parse(readFileSync('project.inlang/settings.json', 'utf8')).locales as string[];
	const catalogues = Object.fromEntries(locales.map((l) => [l, load(l)]));
	const base = catalogues.en ?? {};

	it('hold every message in every language', () => {
		// 🔴 Paraglide compiles a message missing from `fr` without a word and shows the
		// English instead — measured on 2.25. "A missing key is a type error" holds only
		// for a key missing everywhere. The Fluent catalogues had drifted by five keys
		// exactly this way.
		expect(Object.keys(base).length).toBeGreaterThan(400);
		for (const [locale, messages] of Object.entries(catalogues)) {
			expect(Object.keys(messages).sort(), locale).toEqual(Object.keys(base).sort());
		}
	});

	it('give a message the same inputs in every language', () => {
		// A French message naming `{count}` where the English names `{n}` renders the
		// placeholder empty, and the type of `m.x()` is the base locale's.
		for (const [locale, messages] of Object.entries(catalogues)) {
			for (const [key, message] of Object.entries(messages)) {
				expect(inputs(message), `${locale}: ${key}`).toEqual(inputs(base[key]));
			}
		}
	});

	it('are all said somewhere', () => {
		// A message nothing renders is a translation someone keeps up for no reader —
		// 237 of them were left from the egui screens. Read from the sources, walked.
		const walk = (dir: string): string[] =>
			readdirSync(dir).flatMap((name) => {
				const path = join(dir, name);
				if (path === join('src', 'lib', 'paraglide')) return [];
				if (statSync(path).isDirectory()) return walk(path);
				return /\.(svelte|ts)$/.test(name) && !name.endsWith('.test.ts') ? [readFileSync(path, 'utf8')] : [];
			});
		const sources = walk('src').join('\n');
		const said = new Set([...sources.matchAll(/\bm\.([a-z0-9_]+)/g)].map((x) => x[1]));
		expect(said.size).toBeGreaterThan(400);
		expect(Object.keys(base).filter((k) => !said.has(k))).toEqual([]);
	});
});
