import { goto } from '$app/navigation';
import { page } from '$app/state';
import { write, type State } from './listing.ts';

/**
 * Moves a list to `next`, through the URL. A new search or filter starts at the first
 * page — page 7 of the old answer is nothing in particular of the new one — and typing
 * a search is one step back, not one per letter; the field typed into keeps the focus
 * and the page its scroll.
 */
export function go(current: State, next: Partial<State>, filters: { id: string }[]) {
	const reset = 'q' in next || 'filters' in next ? { page: 1 } : {};
	void goto(write(page.url, { ...current, ...reset, ...next }, filters), {
		replace: 'q' in next,
		reset: false
	});
}
