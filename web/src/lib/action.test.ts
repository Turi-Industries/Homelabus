import { describe, expect, it } from 'vitest';
import { panel, replay, type ActionResult, type Proposal } from './action.svelte.ts';
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
