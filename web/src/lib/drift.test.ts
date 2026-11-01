import { describe, expect, it } from 'vitest';
import type { Schemas } from '#lib/api/client.ts';
import { gap } from './drift.ts';

describe('the drift page', () => {
	it('keys two gaps of one application apart', () => {
		const of = (description: string): Schemas['DriftSummary'] => ({
			target: 'vikunja',
			description,
			attention: 'notice',
			corrigible: true,
			refusal: null,
			fix: null
		});
		const both = [of('vikunja: 1 replica instructed, the manifest asks for 2'), of('vikunja: running vikunja:0.24, expected vikunja:0.25')];
		expect(new Set(both.map(gap)).size).toBe(both.length);
	});
});
