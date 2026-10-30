import { afterEach, describe, expect, it, vi } from 'vitest';
import { panel, PASSKEY_CHANNEL, replay, type ActionResult, type Passkey, type Proposal } from './action.svelte.ts';
import type { Schemas } from './api/client.ts';
import type { Answer } from './resource.svelte.ts';

// Only what the panel reads here; an invitation's answer adds the `link` it shows once.
const result = (summary: string, link: string | null = null) => ({ summary, link }) as unknown as ActionResult;
const answer = (r: ActionResult): Answer<ActionResult> => ({ data: r, response: new Response() });

/** A request answered when the test says so. */
function later() {
	let answer: (a: Answer<ActionResult>) => void = () => {};
	const promise = new Promise<Answer<ActionResult>>((resolve) => (answer = resolve));
	return { promise, answer };
}

function proposing(title: string, preview: Promise<Answer<ActionResult>>, applied?: Promise<Answer<ActionResult>>): Proposal {
	return { title, send: (apply) => (apply && applied ? applied : preview), plan: null };
}

describe('the action panel', () => {
	it('drops a preview that answers after another was asked for', async () => {
		const slow = later();
		const first = proposing('first', slow.promise);
		const second = proposing('second', Promise.resolve(answer(result('second'))));
		const asked = panel.propose(first);
		await panel.propose(second);
		slow.answer(answer(result('first')));
		await asked;
		expect(panel.stage.kind === 'previewed' && panel.stage.proposal).toBe(second);
	});

	it('shows what was done even when another preview was opened meanwhile', async () => {
		// Applying creates, say, an invitation whose link is shown once: dropped in favour of
		// a preview anyone can ask for again, it would be gone for good.
		const execution = later();
		const done = proposing('invite', Promise.resolve(answer(result('would invite'))), execution.promise);
		await panel.propose(done);
		const applying = panel.apply(null);
		panel.close();
		await panel.propose(proposing('other', Promise.resolve(answer(result('other')))));
		execution.answer(answer(result('invited', 'https://example.test/signup#invitation=x')));
		await applying;
		expect(panel.stage.kind).toBe('applied');
		expect('result' in panel.stage && 'link' in panel.stage.result && panel.stage.result.link).toBe('https://example.test/signup#invitation=x');
		panel.close();
	});
});

describe('an action that destroys', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		panel.close();
	});

	const url = 'https://id.example/authorize?client_id=hlb&state=s1&prompt=login';
	const waiting = (): Answer<ActionResult> =>
		({
			error: { error: 'this destroys: present your passkey to confirm it' },
			response: new Response(null, { status: 428, headers: { 'x-hlb-passkey-url': url } })
		}) as unknown as Answer<ActionResult>;

	/** A removal whose execution waits for a passkey; what each send carried, kept. */
	function removal() {
		const sent: (Passkey | null | undefined)[] = [];
		const proposal: Proposal = {
			title: 'remove gitea',
			send: (apply, _confirmed, passkey) => {
				if (!apply) return Promise.resolve(answer(result('would remove')));
				sent.push(passkey);
				return Promise.resolve(passkey ? answer(result('removed')) : waiting());
			},
			plan: null
		};
		return { proposal, sent };
	}

	it('waits for a passkey, then sends the action again with what PocketID returned', async () => {
		const opened: string[] = [];
		vi.stubGlobal('window', { open: (u: string) => (opened.push(u), {}) });
		const { proposal, sent } = removal();
		await panel.propose(proposal);
		await panel.apply('gitea');
		// Nothing opened yet: the window waits for a click of its own.
		expect(panel.stage.kind).toBe('passkey');
		expect(opened).toEqual([]);

		const presenting = panel.presentPasskey();
		expect(opened).toEqual([url]);
		const page = new BroadcastChannel(PASSKEY_CHANNEL);
		// Another confirmation's return is not this one.
		page.postMessage({ state: 'other', code: 'c0', error: null });
		page.postMessage({ state: 's1', code: 'c1', error: null });
		await presenting;
		page.close();

		expect(sent).toEqual([undefined, { state: 's1', code: 'c1' }]);
		expect(panel.stage.kind === 'applied' && panel.stage.result.summary).toBe('removed');
	});

	it('sends nothing when PocketID refused, and says so', async () => {
		vi.stubGlobal('window', { open: () => ({}) });
		const { proposal, sent } = removal();
		await panel.propose(proposal);
		await panel.apply('gitea');
		const presenting = panel.presentPasskey();
		const page = new BroadcastChannel(PASSKEY_CHANNEL);
		page.postMessage({ state: 's1', code: null, error: 'access_denied' });
		await presenting;
		page.close();

		expect(sent).toEqual([undefined]);
		expect(panel.stage.kind === 'passkey' && panel.stage.refused).toEqual({ idp: 'access_denied' });
	});

	it('carries the passkey in the headers the controller reads, and only when given', async () => {
		const asked: Request[] = [];
		const fetch = async (r: RequestInfo | URL) => {
			if (r instanceof Request) asked.push(r);
			return new Response('{}', { headers: { 'content-type': 'application/json' } });
		};
		// The real client, its `fetch` and an absolute base given: node has no page to be
		// relative to.
		vi.resetModules();
		vi.doMock('./api/client.ts', async (real) => {
			const client = await real<typeof import('./api/client.ts')>();
			return { ...client, api: client.connect({ baseUrl: 'http://controller.test', fetch }) };
		});
		const { proposal } = await import('./action.svelte.ts');
		vi.doUnmock('./api/client.ts');
		const removal = proposal('remove gitea', 'delete', '/api/apps/{name}', { path: { name: 'gitea' } });
		await removal.send(true, 'gitea', { state: 's1', code: 'c1' });
		await removal.send(false, null);
		const [withPasskey, without] = asked;
		expect(asked).toHaveLength(2);
		expect(withPasskey?.headers.get('x-hlb-passkey-state')).toBe('s1');
		expect(withPasskey?.headers.get('x-hlb-passkey-code')).toBe('c1');
		expect(without?.headers.get('x-hlb-passkey-code')).toBeNull();
	});

	it('says the window was blocked rather than wait for it', async () => {
		vi.stubGlobal('window', { open: () => null });
		const { proposal } = removal();
		await panel.propose(proposal);
		await panel.apply('gitea');
		await panel.presentPasskey();
		expect(panel.stage.kind === 'passkey' && panel.stage.refused).toBe('blocked');
	});
});

describe('a saved plan', () => {
	const filed = (over: Partial<Schemas['NamedPlan']>) =>
		({
			name: 'sunday',
			summary: 'upgrade vikunja',
			method: 'POST',
			path: '/api/apps/vikunja/upgrade',
			body: '',
			route: '/api/apps/{name}/upgrade',
			created_by: 'lena',
			age_s: 60,
			attention: 'ok',
			...over
		}) as Schemas['NamedPlan'];

	it('is proposed again as the very request it was filed with', () => {
		const again = replay('sunday', filed({ body: '{"replicas":2}', path: '/api/apps/vikunja/scale', route: '/api/apps/{name}/scale' }));
		expect(again?.plan).toEqual({ method: 'POST', path: '/api/apps/vikunja/scale', body: '{"replicas":2}' });
	});

	it('is not offered again when no route takes it, or its body is not JSON', () => {
		expect(replay('gone', filed({ route: null }))).toBeNull();
		expect(replay('torn', filed({ body: '{"replicas":' }))).toBeNull();
	});
});
