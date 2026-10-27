import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

/** A page the router serves, as its folder spells it, and the URLs it answers. */
export interface Pattern {
	/** `/apps/[name]/[[tab]]` — groups dropped, parameters kept. */
	id: string;
	/** Whether it sits inside the console's shell. */
	shell: boolean;
	matches: RegExp;
}

/** Every `+page.svelte` under `src/routes`, walked — never a list. */
export function patterns(): Pattern[] {
	const root = join('src', 'routes');
	const walk = (dir: string): string[] =>
		readdirSync(dir).flatMap((name) => {
			const path = join(dir, name);
			if (statSync(path).isDirectory()) return walk(path);
			return name === '+page.svelte' ? [relative(root, dir)] : [];
		});
	return walk(root).map((folder) => {
		const parts = folder.split(sep).filter(Boolean);
		const kept = parts.filter((p) => !/^\(.+\)$/.test(p));
		const source = kept
			.map((p) => (/^\[\[.+\]\]$/.test(p) ? '(?:/[^/]+)?' : /^\[.+\]$/.test(p) ? '/[^/]+' : '/' + p))
			.join('');
		return {
			id: '/' + kept.join('/'),
			shell: parts[0] === '(shell)',
			matches: new RegExp(`^${source || '/'}$`)
		};
	});
}

/**
 * The paths that are the controller's, not the interface's — read from the document,
 * the way the controller and `vite.config.ts` read them: a link there is a download or
 * a sign-in, never a page to render.
 */
export function serverPrefixes(): string[] {
	const document = JSON.parse(readFileSync('openapi.json', 'utf8')) as { paths: object };
	return [...new Set(Object.keys(document.paths).map((p) => '/' + p.split('/')[1]))];
}
