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

// The parser's tree, as far as this scan reads it.
type Node = { type: string; [key: string]: unknown };
type Fragment = { nodes: Node[] };

/** The class names written literally in an expression: strings, arrays, either branch. */
function literals(e: Node | null | undefined): string[] {
	if (!e) return [];
	switch (e.type) {
		case 'Literal':
			return typeof e.value === 'string' ? e.value.split(/\s+/) : [];
		case 'TemplateLiteral':
			return (e.quasis as { value: { cooked: string } }[]).flatMap((q) => q.value.cooked.split(/\s+/));
		case 'ArrayExpression':
			return (e.elements as Node[]).flatMap(literals);
		case 'ConditionalExpression':
			return [...literals(e.consequent as Node), ...literals(e.alternate as Node)];
		case 'LogicalExpression':
			return literals(e.right as Node);
	}
	return [];
}

function classes(element: Node): string[] {
	const attribute = (element.attributes as Node[] | undefined)?.find((a) => a.type === 'Attribute' && a.name === 'class');
	if (attribute === undefined || attribute.value === true) return [];
	const parts = (Array.isArray(attribute.value) ? attribute.value : [attribute.value]) as Node[];
	return parts.flatMap((p) => (p.type === 'Text' ? String(p.data).split(/\s+/) : literals(p.expression as Node)));
}

const ELEMENTS = new Set(['RegularElement', 'Component', 'SvelteElement']);

/**
 * The elements a wrapping row lays out: its direct children, seen through the blocks
 * that do not add a box — and through a snippet it renders, which is how `Row` did it.
 */
function laidOut(fragment: Fragment | null | undefined, snippets: Map<string, Fragment>, seen = new Set<string>()): Node[] {
	return (fragment?.nodes ?? []).flatMap((n) => {
		if (ELEMENTS.has(n.type)) return [n];
		const inner = ['consequent', 'alternate', 'body', 'fallback', 'fragment', 'pending', 'then', 'catch']
			.map((k) => n[k] as Fragment | null | undefined)
			.filter((f) => f && Array.isArray(f.nodes));
		if (n.type === 'SnippetBlock') return [];
		if (n.type === 'RenderTag') {
			const callee = ((n.expression as Node).callee ?? (n.expression as Node).expression) as Node | undefined;
			const name = callee?.type === 'Identifier' ? String(callee.name) : undefined;
			if (name === undefined || seen.has(name)) return [];
			return laidOut(snippets.get(name), snippets, new Set([...seen, name]));
		}
		return inner.flatMap((f) => laidOut(f, snippets, seen));
	});
}

/** Every `flex-1` laid out by a `flex-wrap` row in `source`, as the child's tag. */
export function squeezed(source: string): string[] {
	const root = parse(source, { modern: true }) as unknown as { fragment: Fragment };
	const snippets = new Map<string, Fragment>();
	const all: Node[] = [];
	const walk = (n: unknown) => {
		if (Array.isArray(n)) return n.forEach(walk);
		if (n === null || typeof n !== 'object') return;
		const node = n as Node;
		if (node.type === 'SnippetBlock') snippets.set(String((node.expression as Node).name), node.body as Fragment);
		if (ELEMENTS.has(node.type)) all.push(node);
		for (const [k, v] of Object.entries(node)) if (k !== 'attributes' && k !== 'expression') walk(v);
	};
	walk(root.fragment);
	return all
		.filter((row) => classes(row).includes('flex-wrap'))
		.flatMap((row) => laidOut(row.fragment as Fragment, snippets))
		.filter((child) => classes(child).includes('flex-1'))
		.map((child) => `<${String(child.name)}>`);
}

describe('a wrapping row', () => {
	it('is recognised in each shape a squeezed child has taken', () => {
		// The scan proves nothing unless it matches the cases the contact sheet found.
		const shapes = [
			'<div class="flex flex-wrap gap-2"><p class="min-w-0 flex-1">a</p><span>b</span></div>',
			`<form class="flex flex-wrap"><input class={[x, 'flex-1']} /><button>b</button></form>`,
			'<div class="flex flex-wrap">{#if a}<label class="flex min-w-0 flex-1 flex-col">a</label>{/if}</div>',
			'{#snippet body()}<div class="min-w-0 flex-1">a</div>{/snippet}<a class="flex flex-wrap">{@render body()}</a>'
		];
		for (const shape of shapes) expect(squeezed(shape), shape).not.toEqual([]);
		// A row that does not wrap may share its line however it likes.
		expect(squeezed('<div class="flex gap-2"><p class="flex-1">a</p></div>')).toEqual([]);
	});

	it('never lets a child take a basis of zero', () => {
		// 🔴 A `flex-wrap` line breaks on the children's basis, and `flex-1`'s is 0: it
		// always fits, so the row never wraps and the text is squeezed to a word per line
		// beside its badge and buttons. Nothing overflows, so no width check sees it.
		// What yields is `grow basis-48`.
		const files = components();
		expect(files).toContain(join('src', 'lib', 'ui', 'Row.svelte'));
		const found = files.flatMap((f) => squeezed(readFileSync(f, 'utf8')).map((tag) => `${f}: ${tag}`));
		expect(found).toEqual([]);
	});
});
