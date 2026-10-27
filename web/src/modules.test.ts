import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { describe, expect, it } from 'vitest';
import { modules } from '#lib/modules/index.ts';

/** Every `+page.svelte` under `dir`, as the URL pattern SvelteKit gives it. */
function pages(dir: string): string[] {
	const root = join('src', 'routes', dir);
	const walk = (d: string): string[] =>
		readdirSync(d).flatMap((name) => {
			const path = join(d, name);
			if (statSync(path).isDirectory()) return walk(path);
			return name === '+page.svelte' ? ['/' + relative(root, d).split(sep).filter(Boolean).join('/')] : [];
		});
	return walk(root);
}

describe('the modules', () => {
	const written = pages('(shell)');
	const declared = modules.flatMap((x) => [...x.pages.map((p) => p.path), ...(x.details ?? [])]);

	it('are all found', () => {
		// The floor under the crossings below: a glob that finds nothing passes them.
		expect(modules.length).toBeGreaterThanOrEqual(8);
		expect(written).toContain('/apps');
	});

	it('declare every page written in the shell, and write every page they declare', () => {
		// 🔴 A page absent from its module is reachable by URL only — wasted work. A page
		// declared and not written is an entry leading nowhere. Both are this one test.
		// `/` is the shell's own home, not a module's.
		expect([...declared, '/'].sort()).toEqual([...written].sort());
	});

	it('have unique ids, named after their folder', () => {
		const ids = modules.map((x) => x.id);
		expect(new Set(ids).size).toBe(ids.length);
		const folders = readdirSync(join('src', 'lib', 'modules')).filter((f) =>
			statSync(join('src', 'lib', 'modules', f)).isDirectory()
		);
		expect([...ids].sort()).toEqual(folders.sort());
	});

	it('offer no page twice', () => {
		expect(new Set(declared).size).toBe(declared.length);
	});
});

describe('the pages outside the shell', () => {
	it('are exactly the ones meant to have no navigation', () => {
		// A screen deliberately out of the navigation is named here, so the test above
		// cannot be satisfied by quietly moving a page out of the shell.
		expect(pages('(bare)').sort()).toEqual(['/kiosk', '/signup', '/uptime']);
	});

	it('answer for every cause the controller can file, each exactly once', () => {
		// Walked from the document, not listed: a cause added in Rust and owned by no
		// module would count nowhere in the navigation and sit on the home unfiled.
		const document = JSON.parse(readFileSync('openapi.json', 'utf8')) as {
			components: { schemas: { Cause: { oneOf: { properties: { kind: { enum: string[] } } }[] } } };
		};
		const kinds = document.components.schemas.Cause.oneOf.flatMap((v) => v.properties.kind.enum);
		expect(kinds.length).toBeGreaterThan(30);
		const owners = (kind: string) => modules.filter((x) => (x.causes as string[] | undefined)?.includes(kind)).map((x) => x.id);
		expect(kinds.filter((k) => owners(k).length !== 1).map((k) => [k, owners(k)])).toEqual([]);
	});
});
