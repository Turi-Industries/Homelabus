import type { Schemas } from './client';
import { requires } from './requires';

export type Rights = Schemas['Rights'];
export type Right = keyof Rights;
type Table = typeof requires;
export type Route = keyof Table;

/**
 * Whether `can` lets this person call the route — read from the right the controller
 * itself declares for it, so a page or a button is offered exactly when the request
 * would be accepted.
 *
 * ⚠️ Not access control: the controller decides on every request. This only avoids
 * offering what will be refused, and a missing `can` (not yet known) offers nothing.
 */
export function allowed<P extends Route>(
	can: Rights | undefined,
	path: P,
	method: keyof Table[P] & string
): boolean {
	const right = (requires[path] as Record<string, string>)[method];
	if (right === 'public') return true;
	return can?.[right as Right] ?? false;
}
