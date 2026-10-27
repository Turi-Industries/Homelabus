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
type Node = { type: string; start: number; end: number; [key: string]: unknown };

/** Every node under `n`, the property name of a `a.b` excluded: `b` is not a variable. */
function nodes(n: unknown, out: Node[] = []): Node[] {
	if (Array.isArray(n)) {
		for (const x of n) nodes(x, out);
		return out;
	}
	if (n === null || typeof n !== 'object') return out;
	const node = n as Node;
	if (typeof node.type === 'string') out.push(node);
	for (const [k, v] of Object.entries(node)) {
		if (k === 'property' && node.type === 'MemberExpression' && !node.computed) continue;
		if (k === 'key' && node.type === 'Property' && !node.computed) continue;
		nodes(v, out);
	}
	return out;
}

const CONTROLS = new Set(['form', 'button', 'input', 'select', 'textarea']);
/** Where a click may reveal what it likes: already on top of the page. */
const LAYERS = new Set(['dialog', 'Modal']);
const layer = (n: Node) => LAYERS.has(String(n.name)) && ['RegularElement', 'Component'].includes(n.type);

/** The name a `$state(…)`, `$derived(…)` or `$state.raw(…)` call is, or undefined. */
function rune(init: Node | null | undefined): string | undefined {
	if (init?.type !== 'CallExpression') return undefined;
	const callee = init.callee as Node;
	return String(callee.type === 'MemberExpression' ? (callee.object as Node).name : callee.name);
}

/**
 * The controls a click unfolds INTO the page in `source`: an `{#if}` on a `$state` a
 * click assigns — or on what is derived from one — holding a control, outside a dialog;
 * and a `<details>` holding a control. A message saying how the click went is not
 * caught: it holds no control.
 */
export function unfolded(source: string): string[] {
	// ⚠️ Names are not scoped: an `{@const}` computed from a clicked state taints every
	// variable of that name in the file, a snippet's parameter included. Rename the const.
	const ast = parse(source, { modern: true }) as unknown as { instance: Node | null; fragment: Node };
	const script = nodes(ast.instance);
	const declared = script.filter((n) => n.type === 'VariableDeclarator');
	const state = new Set(declared.filter((n) => rune(n.init as Node) === '$state').map((n) => String((n.id as Node).name)));
	const functions = new Map<string, Node>();
	for (const n of script) {
		if (n.type === 'FunctionDeclaration') functions.set(String((n.id as Node).name), n);
		if (n.type === 'VariableDeclarator' && /Function/.test(String((n.init as Node | null)?.type))) {
			functions.set(String((n.id as Node).name), n.init as Node);
		}
	}

	// What a click writes: in its handler, and in the functions the handler calls.
	const handlers = nodes(ast.fragment)
		.filter((n) => n.type === 'Attribute' && n.name === 'onclick')
		.map((n) => (n.value as Node).expression as Node);
	const written = new Set<string>();
	const followed = new Set<string>();
	const read = (code: Node) => {
		for (const n of nodes(code)) {
			// The variable itself: `draft.accent = null` edits a form, it does not open one.
			if (n.type === 'AssignmentExpression' && (n.left as Node).type === 'Identifier') written.add(String((n.left as Node).name));
			const called = n.type === 'Identifier' ? String(n.name) : undefined;
			if (called !== undefined && functions.has(called) && !followed.has(called)) {
				followed.add(called);
				read(functions.get(called) as Node);
			}
		}
	};
	handlers.forEach(read);
	const clicked = new Set([...written].filter((w) => state.has(w)));
	// And what is computed from it: the catalogue's card read `{@const item = …installing…}`.
	const derivations = [
		...declared.filter((n) => rune(n.init as Node) === '$derived'),
		...nodes(ast.fragment)
			.filter((n) => n.type === 'ConstTag')
			.flatMap((n) => (n.declaration as Node).declarations as Node[])
	].filter((n) => (n.id as Node).type === 'Identifier');
	for (let grew = true; grew; ) {
		grew = false;
		for (const d of derivations) {
			const name = String((d.id as Node).name);
			if (!clicked.has(name) && nodes(d.init).some((x) => x.type === 'Identifier' && clicked.has(String(x.name)))) {
				clicked.add(name);
				grew = true;
			}
		}
	}
	// A control inside a dialog is not unfolded into the page, whoever opens the dialog.
	const holdsControl = (n: unknown): boolean => {
		if (Array.isArray(n)) return n.some(holdsControl);
		if (n === null || typeof n !== 'object') return false;
		const node = n as Node;
		if (layer(node)) return false;
		if (node.type === 'RegularElement' && CONTROLS.has(String(node.name))) return true;
		return Object.entries(node).some(([k, v]) => k !== 'attributes' && holdsControl(v));
	};

	const found: string[] = [];
	const walk = (n: unknown) => {
		if (Array.isArray(n)) return n.forEach(walk);
		if (n === null || typeof n !== 'object') return;
		const node = n as Node;
		if (layer(node)) return;
		if (node.type === 'IfBlock') {
			const reads = nodes(node.test).some((x) => x.type === 'Identifier' && clicked.has(String(x.name)));
			if (reads && holdsControl(node.consequent)) found.push(`{#if ${source.slice((node.test as Node).start, (node.test as Node).end)}}`);
		}
		if (node.type === 'RegularElement' && node.name === 'details') {
			if (holdsControl(node.fragment)) found.push('<details>');
		}
		for (const [k, v] of Object.entries(node)) if (k !== 'attributes' && k !== 'expression' && k !== 'test') walk(v);
	};
	walk(ast.fragment);
	return found;
}

/** Unfolded on purpose, each with its reason: a path and every shape found there. */
const ALLOWED: Record<string, { shapes: string[]; why: string }> = {
	[join('src', 'lib', 'home', 'ProblemsWidget.svelte')]: {
		shapes: ['<details>'],
		why: 'a line set aside stays LISTED, folded under the inbox, with its "bring back": hiding a problem someone deferred is how it is forgotten'
	},
	[join('src', 'routes', '(shell)', '+layout.svelte')]: {
		shapes: ['{#if menuOpen}'],
		why: 'the veil behind the navigation drawer on a phone, a button that closes it'
	}
};

describe('what a button opens', () => {
	it('is recognised in each shape an unfolded form has taken', () => {
		// The scan proves nothing unless it matches the cases that were found.
		const shapes = [
			// The invitation form, folded above its list.
			'<details><summary>New</summary><form><input /></form></details>',
			// The installation, a card drawn above the catalogue by a row's button.
			`<script>let installing = $state(null); function open(i) { installing = i; }</script>
			 {#if installing !== null}<form></form>{/if}<button onclick={() => open(1)}>x</button>`,
			// The mute, a form unfolded inside the alert's row.
			`<script>let muting = $state(null);</script>
			 {#if muting === 'a'}<form></form>{/if}<button onclick={() => (muting = 'a')}>x</button>`,
			// The same, through what is computed from it.
			`<script>let installing = $state(null);</script><button onclick={() => (installing = 1)}>x</button>
			 {#each items as items}{@const item = items.find((i) => i === installing)}{#if item}<button>y</button>{/if}{/each}`,
			// The home's arrangement, a panel of buttons opened by one.
			`<script>let arranging = $state(false);</script>
			 <button onclick={() => (arranging = !arranging)}>x</button>{#if arranging}<div><button>y</button></div>{/if}`
		];
		for (const shape of shapes) expect(unfolded(shape), shape).not.toEqual([]);
		// The same, opened in a modal, is what is asked for — the modal itself under an
		// `{#if}` on what was clicked, as the alerts' is.
		expect(
			unfolded(`<script>let open = $state(false); let rule = $state(null);</script>
			 <button onclick={() => ((rule = 'a'), (open = true))}>x</button>
			 {#if rule !== null}<Modal bind:open title="t"><form></form></Modal>{/if}`)
		).toEqual([]);
		// A state nothing clicks — a draft loaded from the server — is not a disclosure, nor
		// is the word saying how a click went.
		expect(unfolded(`<script>let draft = $state();</script>{#if draft}<form></form>{/if}`)).toEqual([]);
		expect(
			unfolded(`<script>let failure = $state();</script><button onclick={() => (failure = 'no')}>x</button>{#if failure}<p>{failure}</p>{/if}`)
		).toEqual([]);
	});

	it('opens it in a modal, never unfolded into the page', () => {
		// Unfolded, a form pushed the list it belongs to down the page, or appeared above
		// a list scrolled past it, out of sight of the button that asked for it. A modal
		// is on top of the button, says what it is for, and closes on Escape.
		const files = components();
		expect(files.length).toBeGreaterThan(40);
		const found = files.flatMap((f) => {
			// Each allowance covers one occurrence: a second fold in the same file is new.
			const allowed = [...(ALLOWED[f]?.shapes ?? [])];
			return unfolded(readFileSync(f, 'utf8'))
				.filter((shape) => {
					const i = allowed.indexOf(shape);
					if (i >= 0) allowed.splice(i, 1);
					return i < 0;
				})
				.map((shape) => `${f}: ${shape}`);
		});
		expect(found).toEqual([]);
	});
});
