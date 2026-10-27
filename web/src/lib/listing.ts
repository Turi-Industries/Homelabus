import type { Snippet } from 'svelte';

/**
 * What a list shows of its rows: searched, filtered, sorted and cut into pages — held
 * in the URL, so a filtered view survives a reload, can be shared, and Back returns
 * to it. Pure, so the one place a list is narrowed can be tested without a browser.
 */

export interface Column<T> {
	id: string;
	label: () => string;
	/**
	 * What the column sorts on, what the search reads and what an export writes. A column
	 * without one is drawn but neither sorted nor searched.
	 */
	value?: (row: T) => string | number | null;
	/** Figures line up on their units: right-aligned, tabular. */
	numeric?: boolean;
	/** Hidden on a phone — what goes when 360 px cannot hold every column. */
	wide?: boolean;
	/** How the cell is drawn, when its value alone does not say enough. */
	cell?: Snippet<[T]>;
}

export interface Filter<T> {
	id: string;
	label: () => string;
	options: { value: string; label: () => string }[];
	test: (row: T, value: string) => boolean;
}

export interface State {
	q: string;
	sort: string | null;
	desc: boolean;
	page: number;
	filters: Record<string, string>;
}

/** Rows a page holds: enough to scan, few enough that the page stays a page. */
export const PAGE = 50;

export function parse(params: Pick<URLSearchParams, 'get' | 'has'>, filters: { id: string }[]): State {
	const page = Number(params.get('page') ?? '1');
	return {
		q: params.get('q') ?? '',
		sort: params.get('sort'),
		desc: params.get('dir') === 'desc',
		page: Number.isInteger(page) && page > 0 ? page : 1,
		filters: Object.fromEntries(filters.flatMap((f) => (params.has(f.id) ? [[f.id, params.get(f.id) ?? '']] : [])))
	};
}

/** `url` with `state` written into its query; what is at its default is left out. */
export function write(url: { pathname: string; search: string }, state: State, filters: { id: string }[]): string {
	const params = new URLSearchParams(url.search);
	const set = (key: string, value: string | null) => (value ? params.set(key, value) : params.delete(key));
	set('q', state.q.trim() === '' ? null : state.q);
	set('sort', state.sort);
	set('dir', state.sort !== null && state.desc ? 'desc' : null);
	set('page', state.page > 1 ? String(state.page) : null);
	for (const f of filters) set(f.id, state.filters[f.id] ?? null);
	const query = params.toString();
	return url.pathname + (query === '' ? '' : `?${query}`);
}

/** "Léna" is found by typing "lena": a search box is typed fast, and accents are not. */
function folded(text: string): string {
	return text.normalize('NFD').replace(/\p{Diacritic}/gu, '').toLowerCase();
}

export interface View<T> {
	shown: T[];
	/** Rows the search and the filters keep, before the page cut. */
	matched: number;
	pages: number;
	page: number;
}

export function view<T>(rows: T[], columns: Column<T>[], filters: Filter<T>[], state: State, size = PAGE): View<T> {
	const words = folded(state.q).split(/\s+/).filter(Boolean);
	const searched = columns.filter((c) => c.value !== undefined);
	let kept = rows.filter((row) => {
		const text = folded(searched.map((c) => String(c.value?.(row) ?? '')).join(' '));
		return words.every((w) => text.includes(w)) && filters.every((f) => {
			const value = state.filters[f.id];
			return value === undefined || value === '' || f.test(row, value);
		});
	});

	const by = columns.find((c) => c.id === state.sort)?.value;
	if (by !== undefined) {
		const sign = state.desc ? -1 : 1;
		// Stable, and "nothing" last whichever way: an unknown is not the smallest value.
		kept = kept
			.map((row, i) => ({ row, i, v: by(row) }))
			.sort((a, b) => {
				if (a.v === null || b.v === null) return a.v === b.v ? a.i - b.i : a.v === null ? 1 : -1;
				const order = typeof a.v === 'number' && typeof b.v === 'number' ? a.v - b.v : String(a.v).localeCompare(String(b.v));
				return order * sign || a.i - b.i;
			})
			.map((x) => x.row);
	}

	const pages = Math.max(1, Math.ceil(kept.length / size));
	const page = Math.min(state.page, pages);
	return { shown: kept.slice((page - 1) * size, page * size), matched: kept.length, pages, page };
}
