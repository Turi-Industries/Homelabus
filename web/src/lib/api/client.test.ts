import { describe, expect, it } from 'vitest';
import { connect, UI_HEADER } from './client';

/** A client whose requests are kept instead of sent. */
function recording() {
	const sent: Request[] = [];
	const client = connect({
		baseUrl: 'http://controller.test',
		fetch: async (input: RequestInfo | URL) => {
			sent.push(input as Request);
			return Response.json({ error: 'refused' }, { status: 403 });
		}
	});
	return { client, sent };
}

describe('the client', () => {
	it('sends the CSRF header on a mutating request', async () => {
		// 🔴 Without it the controller refuses every cookie-authenticated mutation — the
		// protection against a form posted from another site.
		const { client, sent } = recording();
		await client.PUT('/api/preferences/theme', { body: { theme: 'Dark' } });
		expect(sent).toHaveLength(1);
		expect(sent[0]?.method).toBe('PUT');
		expect(sent[0]?.headers.get(UI_HEADER)).not.toBeNull();
	});

	it('sends the session cookie to its own origin, and only there', async () => {
		const { client, sent } = recording();
		await client.GET('/api/me');
		expect(sent[0]?.credentials).toBe('same-origin');
		expect(sent[0]?.url).toBe('http://controller.test/api/me');
	});

	it('acts only when told to', async () => {
		// Preview by default: the query that makes an action route act is spelled by the
		// caller, never added by the client.
		const { client, sent } = recording();
		await client.POST('/api/apps/{name}/install', {
			params: { path: { name: 'gitea' } },
			body: {}
		});
		expect(sent[0]?.url).toBe('http://controller.test/api/apps/gitea/install');
	});
});
