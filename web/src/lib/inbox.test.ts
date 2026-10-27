import { describe, expect, it } from 'vitest';
import type { Issue } from './causes.ts';
import { concerning, lines } from './inbox.svelte.ts';
import { modules } from './modules/index.ts';

const issue = (kind: string, attention: Issue['attention'], subjects: string[], aside_until: number | null = null): Issue =>
	({ cause: { kind }, attention, subjects, aside_until }) as Issue;

describe('the inbox', () => {
	const all = lines([
		issue('account_without_mailbox', 'critical', ['alix', 'camille', 'dominique']),
		issue('one_fresh_copy', 'notice', ['immich']),
		issue('admin_unknown', 'ok', []),
		issue('safeguard', 'critical', ['two-passkeys'], 2_000_000_000)
	]);

	it('is one line a cause, naming what it covers, never one a subject', () => {
		expect(all).toHaveLength(3);
		expect(all[0]?.detail).toBe('alix, camille, dominique');
		expect(all[0]?.href).toBe('/accounts?state=without-mailbox');
		// About one thing, the line leads to that thing.
		expect(all[1]?.href).toBe('/apps/immich/backups');
	});

	it('leads several partial apps to a list that shows them all', () => {
		// They are `notice` unless their backups are late: filtered on `critical`, the list
		// the line led to hid them.
		const [partial] = lines([issue('app_partial', 'notice', ['immich', 'vikunja'])]);
		expect(partial?.href).toBe('/apps');
	});

	it('counts causes on a module, not the people they cover, nor what was set aside', () => {
		const people = modules.find((x) => x.id === 'people');
		expect(people && concerning(all, people)).toEqual({ count: 1, critical: true });
	});
});
