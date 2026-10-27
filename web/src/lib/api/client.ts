import createClient from 'openapi-fetch';
import type { components, paths } from './schema';

export type Schemas = components['schemas'];

/**
 * The header the controller requires on every mutating request authenticated by its
 * session cookie — the CSRF protection: a browser adds a custom header only to a
 * same-origin `fetch`, and a cross-origin request carrying one triggers a preflight the
 * controller does not satisfy. Sent on reads too, so no call can forget it.
 */
export const UI_HEADER = 'x-hlb-ui';

/**
 * A client for the controller. Paths, verbs, parameters and bodies are checked against
 * the OpenAPI document the controller is built from: a renamed route is a type error
 * here, not a 404 on screen.
 *
 * 🔴 The only way the interface reaches the API — `every_call_goes_through_the_client`
 * refuses a bare `fetch` anywhere else, since that is a call without the header.
 */
export function connect(options: { baseUrl?: string; fetch?: typeof globalThis.fetch } = {}) {
	return createClient<paths>({
		baseUrl: options.baseUrl ?? '',
		fetch: options.fetch,
		credentials: 'same-origin',
		headers: { [UI_HEADER]: '1' }
	});
}

/** The client the screens use: same origin as the page, which the controller serves. */
export const api = connect();
