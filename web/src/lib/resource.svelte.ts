import type { PathsWithMethod, RequiredKeysOf, SuccessResponseJSON } from 'openapi-typescript-helpers';
import { api } from './api/client';
import type { paths } from './api/schema';

export type Readable = PathsWithMethod<paths, 'get'>;
export type BodyOf<P extends Readable> = SuccessResponseJSON<paths[P]['get']>;
type Parameters<P extends Readable> = paths[P]['get'] extends { parameters: infer X } ? X : never;
type Params<P extends Readable> = Omit<Parameters<P>, 'header' | 'cookie'>;
type Arguments<P extends Readable> =
	RequiredKeysOf<Params<P>> extends never ? [params?: Params<P>] : [params: Params<P>];

/** How long a request may take before it is abandoned and counted as a failure. */
const TIMEOUT_MS = 10_000;
/** How often a watched resource asks again. */
const EVERY_MS = 15_000;
/**
 * The routes that change more slowly than that, and how often they do: asking more often
 * spends a household's shared read budget for the same answer. The history is recorded
 * once a minute; the version changes with an upgrade.
 */
const SLOWER: Partial<Record<Readable, number>> = { '/api/history': 60_000, '/healthz': 3_600_000 };

/**
 * One endpoint's answer, as the interface knows it: the last data received, WHEN it
 * was received, and whether the last attempt failed.
 *
 * 🔴 Stale data must never look fresh. A failed refresh keeps the previous data — the
 * last known state is worth showing — but sets `error`, and `Freshness` then says the
 * controller is unreachable and how old what follows is. Dropping the data would hide
 * the state; keeping it silently would lie about it.
 */
export class Resource<T> {
	data = $state.raw<T | undefined>();
	error = $state<string | undefined>();
	/** The HTTP status of the last refusal: a 401 is "signed out", not "broken". */
	status = $state<number | undefined>();
	/** When the data was received, in milliseconds since the epoch. */
	received = $state<number | undefined>();
	pending = $state(false);

	#load: (signal: AbortSignal) => Promise<Answer<T>>;
	#every: number;
	#turn = 0;
	#watchers = 0;
	#timer: ReturnType<typeof setInterval> | undefined;

	constructor(load: (signal: AbortSignal) => Promise<Answer<T>>, every = EVERY_MS) {
		this.#load = load;
		this.#every = every;
	}

	/** Whether something on screen reads it now. */
	get watched(): boolean {
		return this.#watchers > 0;
	}

	async refresh(): Promise<void> {
		// 🔴 Numbered: a request abandoned on timeout can still answer afterwards, and
		// adopted then it would be dated now while describing minutes ago.
		const turn = ++this.#turn;
		this.pending = true;
		try {
			const answer = await this.#load(AbortSignal.timeout(TIMEOUT_MS));
			if (turn !== this.#turn) return;
			if (answer.data !== undefined) {
				this.data = answer.data;
				this.received = Date.now();
				this.error = undefined;
				this.status = undefined;
			} else {
				this.error = refusal(answer.error, answer.response);
				this.status = answer.response.status;
			}
		} catch (e) {
			if (turn !== this.#turn) return;
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			if (turn === this.#turn) this.pending = false;
		}
	}

	/**
	 * Keeps the resource fresh while something on screen reads it; returns what stops
	 * that. Meant for `$effect(() => resource.watch())`.
	 */
	watch(): () => void {
		if (this.#watchers++ === 0) {
			void this.refresh();
			// A tab nobody looks at asks nothing: a household's forgotten tabs share the
			// controller's per-address budget with the one in use. Coming back asks at once.
			this.#timer = setInterval(() => {
				if (document.visibilityState === 'visible') void this.refresh();
			}, this.#every);
		}
		return () => {
			if (--this.#watchers === 0) clearInterval(this.#timer);
		};
	}
}

export type Answer<T> = { data?: T; error?: unknown; response: Response };

/** What a refusal says: the controller's `ErrorBody`, else the status. */
export function refusal(error: unknown, response: Response): string {
	if (typeof error === 'object' && error !== null && 'error' in error) {
		return String((error as { error: unknown }).error);
	}
	return `${response.status} ${response.statusText}`.trim();
}

const shared = new Map<string, Resource<unknown>>();

/**
 * The resource for a GET route — the same instance for every reader of the same route
 * and parameters, so the home and a module's page share one request and one freshness.
 */
export function read<P extends Readable>(path: P, ...[params]: Arguments<P>): Resource<BodyOf<P>> {
	const key = `${path} ${JSON.stringify(params ?? {})}`;
	let resource = shared.get(key);
	if (resource === undefined) {
		// The generic `path` defeats openapi-fetch's per-route overloads; the signature
		// above is what checks the path and its parameters.
		const get = api.GET as unknown as (
			path: string,
			init: { params?: unknown; signal: AbortSignal }
		) => Promise<Answer<unknown>>;
		resource = new Resource((signal) => get(path, { params, signal }), SLOWER[path]);
		shared.set(key, resource);
	}
	return resource as Resource<BodyOf<P>>;
}

/** Asks again for everything on screen — after an action, which may have changed any of it. */
export async function refreshAll(): Promise<void> {
	await Promise.all([...shared.values()].filter((r) => r.watched).map((r) => r.refresh()));
}

/** Every resource something on screen is reading: what the shell's freshness summarises. */
export function watched(): Resource<unknown>[] {
	return [...shared.values()].filter((r) => r.watched);
}
