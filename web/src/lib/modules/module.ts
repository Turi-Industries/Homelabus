import type House from '@lucide/svelte/icons/house';
import type { Schemas } from '#lib/api/client.ts';
import { allowed, type Rights, type Route } from '#lib/api/rights.ts';
import type { CauseKind } from '#lib/causes.ts';
import { read, type Readable } from '#lib/resource.svelte.ts';

export type Attention = Schemas['Attention'];

/** A page a module offers: one entry in its tab bar, one route folder. */
export interface Page {
	/** The URL, exactly as the route folder under `src/routes/(shell)` spells it. */
	path: string;
	label: () => string;
	/**
	 * The GET routes the page reads. It is offered to whoever may call every one of
	 * them — the right comes from the controller's document, never written here.
	 */
	reads: Readable[];
	/**
	 * For a page that exists to change something: offered only if one of these is
	 * allowed too. Announcements are READ by everyone; the page that writes them is not
	 * for everyone.
	 */
	writes?: [method: string, route: Route][];
}

/** An entry `Ctrl+K` can find, besides the pages. */
export interface Entry {
	label: string;
	hint: string;
	href: string;
}

/**
 * A part of the interface that declares itself: navigation, tab bars, the inbox and
 * the command palette are built from these, never from a list kept beside them.
 */
export interface Module {
	id: string;
	/** Where the module sits: `console` in the navigation, `me` in the person's own corner. */
	area: 'console' | 'me';
	/** Navigation order, smallest first. */
	order: number;
	label: () => string;
	/** One of Lucide's icons. */
	icon: typeof House;
	/** The first page is where the navigation entry leads. */
	pages: [Page, ...Page[]];
	/**
	 * Route folders that are details, not tabs — `/apps/[name]` — reached by clicking,
	 * never from the navigation.
	 */
	details?: string[];
	/**
	 * The causes this module answers for: an issue the controller files under one of
	 * them counts on the module's navigation entry and is shown with it on the home.
	 * `modules.test.ts` holds every cause the document knows to exactly one module.
	 */
	causes?: CauseKind[];
	/** Things to find by name: the applications, the machines. */
	search?: { path: Readable; entries: (data: unknown) => Entry[] };
}

export function offered(page: Page, can: Rights | undefined): boolean {
	return (
		page.reads.every((path) => allowed(can, path, 'GET')) &&
		(page.writes === undefined || page.writes.some(([method, route]) => allowed(can, route, method as never)))
	);
}

/** The pages of a module this person is offered. */
export function pagesFor(module: Module, can: Rights | undefined): Page[] {
	return module.pages.filter((p) => offered(p, can));
}

/** The resource behind a search, shared with every page reading the same route. */
export function source(path: Readable) {
	return read(path as '/api/apps');
}
