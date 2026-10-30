import { allowed, allowedAt, type Rights, type Route } from '#lib/api/rights.ts';
import { read } from '#lib/resource.svelte.ts';

/** Who is looking: read once by the shell, shared with every page through the cache. */
export function me() {
	return read('/api/me');
}

/** What the person may do — `undefined` until the shell has read it, which offers nothing. */
export function rights(): Rights | undefined {
	return me().data?.can;
}

/** Whether to offer a button that calls this route. */
export function may<P extends Route>(path: P, method: Parameters<typeof allowed<P>>[2]): boolean {
	return allowed(rights(), path, method);
}

/** [`may`] for a route the controller names at run time: a saved plan's. */
export function mayAt(path: string, method: string): boolean {
	return allowedAt(rights(), path, method);
}
