import { describe, expect, it } from 'vitest';
import { daysAgo, moment } from './format.ts';

// A zone east of UTC, with a summer time: in UTC itself, local and UTC readings agree and
// neither test below could fail. Node re-reads `TZ` when it is assigned.
process.env.TZ = 'Europe/Paris';

describe('a moment the server wrote', () => {
	const at = Date.UTC(2026, 9, 21, 14, 3, 0);

	it('runs in a zone where local time is not UTC', () => {
		expect(new Date(at).getTimezoneOffset()).toBe(-120);
	});

	it("reads SQLite's zone-less datetime as UTC, not as local time", () => {
		expect(moment('2026-10-21 14:03:00').getTime()).toBe(at);
		expect(moment('2026-10-21T14:03:00').getTime()).toBe(at);
		expect(moment('2026-10-21 14:03:00.250').getTime()).toBe(at + 250);
	});

	it('keeps RFC 3339 and seconds since the epoch as they are', () => {
		expect(moment('2026-10-21T14:03:00Z').getTime()).toBe(at);
		expect(moment('2026-10-21T16:03:00+02:00').getTime()).toBe(at);
		expect(moment(at / 1000).getTime()).toBe(at);
	});
});

describe('days ago', () => {
	// Clocks went forward in Paris in the night of 28 to 29 March 2026: the 29th has 23 hours.
	const now = new Date(2026, 2, 30, 10, 0).getTime();
	const local = (day: number, hour: number) => new Date(2026, 2, day, hour, 0).getTime() / 1000;

	it('counts calendar days across the night clocks go forward', () => {
		expect(daysAgo(local(30, 0), now)).toBe(0);
		expect(daysAgo(local(29, 23), now)).toBe(1);
		expect(daysAgo(local(28, 22), now)).toBe(2);
		expect(daysAgo(local(27, 12), now)).toBe(3);
	});
});
