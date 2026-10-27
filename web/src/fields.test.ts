import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'svelte/compiler';
import { describe, expect, it } from 'vitest';

/** Every component under `src/`: walked, never listed. */
function components(dir = 'src'): string[] {
	return readdirSync(dir).flatMap((name) => {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) return components(path);
		return name.endsWith('.svelte') ? [path] : [];
	});
}

type Node = { type: string; name?: string; attributes?: { type: string; name: string; value: unknown }[]; [key: string]: unknown };

/** Types that hold no typed text and no number: nothing to bound. */
const CHOSEN = new Set(['checkbox', 'radio', 'file', 'color', 'hidden', 'range']);

/** The fields in `source` that take more than they should, as `<tag type>: missing`. */
export function unbounded(source: string): string[] {
	const found: string[] = [];
	const walk = (n: unknown) => {
		if (Array.isArray(n)) return n.forEach(walk);
		if (n === null || typeof n !== 'object') return;
		const node = n as Node;
		if (node.type === 'RegularElement' && (node.name === 'input' || node.name === 'textarea')) {
			const has = (a: string) => node.attributes?.some((x) => x.type === 'Attribute' && x.name === a) ?? false;
			const typeAttr = node.attributes?.find((x) => x.type === 'Attribute' && x.name === 'type');
			const type = node.name === 'textarea' ? 'textarea' : typeAttr === undefined ? 'text' : (((typeAttr.value as { data?: string }[])[0]?.data ?? '?') as string);
			if (type === 'number') {
				const missing = ['min', 'max'].filter((a) => !has(a));
				if (missing.length > 0) found.push(`<input type=number>: ${missing.join(', ')}`);
			} else if (!CHOSEN.has(type) && !has('maxlength')) {
				found.push(`<${node.name} type=${type}>: maxlength`);
			}
		}
		for (const [k, v] of Object.entries(node)) if (k !== 'attributes') walk(v);
	};
	walk((parse(source, { modern: true }) as unknown as { fragment: Node }).fragment);
	return found;
}

describe('a field', () => {
	it('is recognised in each shape an unbounded one has taken', () => {
		expect(unbounded('<input bind:value={note} />')).toEqual(['<input type=text>: maxlength']);
		expect(unbounded('<textarea bind:value={body}></textarea>')).toEqual(['<textarea type=textarea>: maxlength']);
		expect(unbounded('<input type="number" min="1" bind:value={uses} />')).toEqual(['<input type=number>: max']);
		expect(unbounded('<input type="checkbox" bind:checked={pinned} />')).toEqual([]);
		expect(unbounded('<input maxlength={limits.X.y.maxLength} />')).toEqual([]);
	});

	it('takes no more than the controller will', () => {
		// 🔴 A field the browser lets run on is a refusal after the click, or worse, a
		// value the server used to cut to fit without a word: ninety days of invitation
		// became thirty. Each bound comes from `#lib/api/limits.ts`, generated from the
		// numbers the controller refuses past.
		const files = components();
		expect(files.length).toBeGreaterThan(40);
		const found = files.flatMap((f) => unbounded(readFileSync(f, 'utf8')).map((x) => `${f}: ${x}`));
		expect(found).toEqual([]);
	});
});
