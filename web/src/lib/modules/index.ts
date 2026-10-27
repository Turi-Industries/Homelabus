import type { Module } from './module';

/**
 * Every module, found by walking `./<id>/module.ts` — a module written is a module in
 * the navigation, with nobody having to remember to add it to a list.
 */
const found = import.meta.glob<{ module: Module }>('./*/module.ts', { eager: true });

export const modules: Module[] = Object.values(found)
	.map((f) => f.module)
	.sort((a, b) => a.order - b.order);

/** The module a URL belongs to: the one with the longest page or detail prefix. */
export function moduleOf(pathname: string): Module | undefined {
	let best: { module: Module; length: number } | undefined;
	for (const module of modules) {
		const paths = [...module.pages.map((p) => p.path), ...(module.details ?? [])];
		for (const path of paths) {
			const prefix = path.split('/[')[0] ?? path;
			const hit = pathname === prefix || pathname.startsWith(prefix + '/');
			if (hit && (best === undefined || prefix.length > best.length)) {
				best = { module, length: prefix.length };
			}
		}
	}
	return best?.module;
}
