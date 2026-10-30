import type { OperationRequestBodyContent } from 'openapi-typescript-helpers';
import { api, type Schemas } from './api/client';
import type { paths } from './api/schema';
import { refreshAll, refusal, type Answer } from './resource.svelte';

export type ActionResult = Schemas['ActionResult'];

/**
 * The request behind an action, as one function of the only two things that differ
 * between its preview and its execution: `apply`, and the target repeated by the
 * person when the preview asked for it.
 *
 * 🔴 Captured whole when the action is proposed. Applying calls the SAME function the
 * preview came from — no form state is read again in between — so what is applied is
 * what was read, which is the guarantee "rebuilt from the preview" exists for.
 */
export type Send = (
	apply: boolean,
	confirmed: string | null,
	passkey?: Passkey | null
) => Promise<Answer<ActionResult>>;

/** What PocketID's return carried, sent again with an action that destroys. */
export interface Passkey {
	state: string;
	code: string;
}

/** Where the page PocketID returns to says what it carried. */
export const PASSKEY_CHANNEL = 'hlb-passkey';

/** The headers a passkey rides on, and the one a 428 names PocketID's address in. */
const passkeyHeaders = (p: Passkey | null | undefined) =>
	p ? { 'x-hlb-passkey-state': p.state, 'x-hlb-passkey-code': p.code } : {};
const PASSKEY_URL = 'x-hlb-passkey-url';

export interface Proposal {
	/** What the person asked for, in their words: the panel's title. */
	title: string;
	send: Send;
	/** The same request as a saved plan records it: method, path and body. `null` for
	 * what is sent at once, which has no preview to replay. */
	plan: { method: Schemas['PlanRequest']['method']; path: string; body: string | null } | null;
}

type Verb = 'post' | 'put' | 'delete';
type Previewable = {
	[P in keyof paths]: {
		[V in Verb]: paths[P][V] extends { parameters: { query?: { apply?: boolean } } } ? V : never;
	}[Verb] extends never
		? never
		: P;
}[keyof paths];

/**
 * An action, built from its route and the values it is sent with — the one way a page
 * proposes something, so the preview, the execution and the plan saved for later are
 * three uses of the same values.
 */
export function proposal<P extends Previewable, V extends Verb & keyof paths[P]>(
	title: string,
	verb: V,
	path: P,
	values: {
		path?: Record<string, string | number>;
		body?: OperationRequestBodyContent<paths[P][V]>;
	} = {}
): Proposal {
	const concrete = path.replace(/\{(\w+)\}/g, (_, k: string) =>
		encodeURIComponent(String(values.path?.[k] ?? ''))
	);
	const call = api[verb.toUpperCase() as 'POST'] as unknown as (
		path: string,
		init: object
	) => Promise<Answer<ActionResult>>;
	return {
		title,
		send: (apply, confirmed, passkey) =>
			call(path, {
				params: { path: values.path, query: { apply } },
				headers: passkeyHeaders(passkey),
				// Only app removal asks for a repeated name, in a body of its own.
				body: confirmed === null ? values.body : { ...(values.body ?? {}), confirmed }
			}),
		plan: {
			method: verb === 'post' ? 'POST' : verb === 'put' ? 'PUT' : 'DELETE',
			path: concrete,
			body: values.body === undefined ? null : JSON.stringify(values.body)
		}
	};
}

/**
 * A saved plan proposed again: its request as it was filed, previewed anew — what it
 * describes may have changed since, and applying still takes the panel's three beats.
 * `null` when it cannot be replayed: no route takes it any more, or its body is not
 * the JSON a preview sends.
 */
export function replay(title: string, plan: Schemas['NamedPlan']): Proposal | null {
	if (plan.route === null) return null;
	let body: object | undefined;
	try {
		body = plan.body === '' ? undefined : (JSON.parse(plan.body) as object);
	} catch {
		return null;
	}
	const method = plan.method as Schemas['PlanRequest']['method'];
	// The path is the concrete one filed — no template left for the client to fill.
	const call = api[method as 'POST'] as unknown as (
		path: string,
		init: object
	) => Promise<Answer<ActionResult>>;
	return {
		title,
		send: (apply, confirmed, passkey) =>
			call(plan.path, {
				params: { query: { apply } },
				headers: passkeyHeaders(passkey),
				body: confirmed === null ? body : { ...(body ?? {}), confirmed }
			}),
		plan: { method, path: plan.path, body: plan.body === '' ? null : plan.body }
	};
}

type Stage =
	| { kind: 'closed' }
	| { kind: 'previewing'; proposal: Proposal }
	| { kind: 'previewed'; proposal: Proposal; result: ActionResult }
	| { kind: 'applying'; proposal: Proposal; result: ActionResult }
	/** Applying destroys: it waits for a passkey presented at `url`, opened by a click
	 * of its own — a window opened after the request came back is one the browser may
	 * block, its click spent. */
	| {
			kind: 'passkey';
			proposal: Proposal;
			result: ActionResult;
			confirmed: string | null;
			url: string;
			waiting: boolean;
			/** Why the last attempt brought nothing back: the window blocked, no answer in
			 * time, or what PocketID said. */
			refused: 'blocked' | 'timeout' | { idp: string } | null;
	  }
	| { kind: 'applied'; proposal: Proposal; result: ActionResult }
	| { kind: 'failed'; proposal: Proposal; error: string };

/**
 * The action panel's state. It lives in the shell, not in a page: a preview asked for
 * from any page is shown in the same place, and never fires with nothing displayed.
 */
class Panel {
	// Raw: a deep proxy would wrap the proposal, and the identity check that drops a
	// preview answering after another was asked for would never match.
	stage = $state.raw<Stage>({ kind: 'closed' });

	/** Asks for the preview — which changes nothing — and opens the panel on it. */
	async propose(proposal: Proposal): Promise<void> {
		this.stage = { kind: 'previewing', proposal };
		const outcome = await settle(proposal.send(false, null));
		if (this.stage.kind !== 'previewing' || this.stage.proposal !== proposal) return;
		this.stage =
			outcome.result === undefined
				? { kind: 'failed', proposal, error: outcome.error }
				: { kind: 'previewed', proposal, result: outcome.result };
	}

	async apply(confirmed: string | null): Promise<void> {
		if (this.stage.kind !== 'previewed') return;
		const { proposal, result } = this.stage;
		this.stage = { kind: 'applying', proposal, result };
		const sent = proposal.send(true, confirmed);
		const url = await passkeyAsked(sent);
		if (url !== null) {
			this.stage = { kind: 'passkey', proposal, result, confirmed, url, waiting: false, refused: null };
			return;
		}
		await this.finish(proposal, sent);
	}

	/**
	 * Opens PocketID for the passkey the action waits for — from the click itself — and
	 * sends the action again with what came back.
	 */
	async presentPasskey(): Promise<void> {
		const asked = this.stage;
		if (asked.kind !== 'passkey') return;
		const opened = window.open(asked.url, 'hlb-passkey', 'popup,width=480,height=720');
		if (opened === null) {
			this.stage = { ...asked, refused: 'blocked' };
			return;
		}
		// Opened again, the window closed by mistake: the return is already awaited.
		if (asked.waiting) return;
		const state = new URL(asked.url).searchParams.get('state');
		this.stage = { ...asked, waiting: true, refused: null };
		const back = await returned(state);
		// Closed, or another action asked for meanwhile: this one is left as it was.
		if (this.stage.kind !== 'passkey' || this.stage.proposal !== asked.proposal) return;
		if (back === null || 'error' in back) {
			this.stage = { ...asked, waiting: false, refused: back === null ? 'timeout' : { idp: back.error } };
			return;
		}
		const { proposal, result, confirmed } = asked;
		this.stage = { kind: 'applying', proposal, result };
		await this.finish(proposal, proposal.send(true, confirmed, back));
	}

	private async finish(proposal: Proposal, sent: Promise<Answer<ActionResult>>): Promise<void> {
		const outcome = await settle(sent);
		// 🔴 No identity check here, unlike a preview: this is what WAS done, and it may
		// carry a link shown once. Closed or showing another preview since, the panel
		// shows it anyway — a preview is asked again with one click, the link never.
		this.stage =
			outcome.result === undefined
				? { kind: 'failed', proposal, error: outcome.error }
				: { kind: 'applied', proposal, result: outcome.result };
		// Whatever the action touched, every screen should show it now rather than at
		// the next tick.
		void refreshAll();
	}

	/**
	 * For the few routes that declare no preview — creating one's own mailbox: sent at
	 * once, and the panel shows what was done rather than what would be.
	 */
	async immediate(title: string, send: () => Promise<Answer<ActionResult>>): Promise<void> {
		const proposal: Proposal = {
			title,
			send: () => send(),
			plan: null
		};
		this.stage = { kind: 'previewing', proposal };
		// Done, not previewed: shown whatever the panel shows by now, like `apply`.
		const outcome = await settle(send());
		this.stage =
			outcome.result === undefined
				? { kind: 'failed', proposal, error: outcome.error }
				: { kind: 'applied', proposal, result: outcome.result };
		void refreshAll();
	}

	close(): void {
		this.stage = { kind: 'closed' };
	}
}

/** PocketID's address when the answer is a 428 waiting for a passkey, else `null`. */
async function passkeyAsked(sent: Promise<Answer<ActionResult>>): Promise<string | null> {
	try {
		const { response } = await sent;
		return response.status === 428 ? response.headers.get(PASSKEY_URL) : null;
	} catch {
		return null;
	}
}

/**
 * What the page PocketID returns to says for the confirmation begun with `state` —
 * `null` once the confirmation would have expired anyway. Another tab's return, or a
 * stale one, is not this one: matched on the state.
 */
function returned(state: string | null, within_ms = 5 * 60_000): Promise<Passkey | { error: string } | null> {
	return new Promise((resolve) => {
		const channel = new BroadcastChannel(PASSKEY_CHANNEL);
		const done = (v: Passkey | { error: string } | null) => {
			clearTimeout(timer);
			channel.close();
			resolve(v);
		};
		const timer = setTimeout(() => done(null), within_ms);
		channel.onmessage = (e: MessageEvent) => {
			const back = e.data as { state?: unknown; code?: unknown; error?: unknown };
			if (state === null || back?.state !== state) return;
			if (typeof back.error === 'string') done({ error: back.error });
			else if (typeof back.code === 'string') done({ state, code: back.code });
		};
	});
}

/**
 * An action's answer: its plan, whether it was planned (200) or refused as
 * unplannable (422, the same shape with `blockers` saying why) — else the refusal.
 */
async function settle(
	answer: Promise<Answer<ActionResult>>
): Promise<{ result: ActionResult; error?: never } | { result?: never; error: string }> {
	try {
		const { data, error, response } = await answer;
		if (data !== undefined) return { result: data };
		if (typeof error === 'object' && error !== null && 'blockers' in error) {
			return { result: error as ActionResult };
		}
		return { error: refusal(error, response) };
	} catch (e) {
		return { error: e instanceof Error ? e.message : String(e) };
	}
}

export const panel = new Panel();
