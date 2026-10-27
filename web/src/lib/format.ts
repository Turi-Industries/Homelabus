import { m } from '#lib/paraglide/messages.js';
import { getLocale } from '#lib/paraglide/runtime.js';

/**
 * A figure as this language writes it: `12 345` in French, `12,345` in English.
 *
 * ⚠️ Paraglide inserts a number into a message as it is. A message whose figure can
 * reach four digits takes the string this returns; a plural takes the number to choose
 * its form — so a figure that can grow large is never a plural's display.
 */
export function number(n: number, digits = 0): string {
	return new Intl.NumberFormat(getLocale(), { maximumFractionDigits: digits }).format(n);
}

/** A fraction `0…1` as a percentage. */
export function percent(fraction: number): string {
	return new Intl.NumberFormat(getLocale(), { style: 'percent', maximumFractionDigits: 0 }).format(
		fraction
	);
}

/** A size in megabytes, in the largest unit that keeps it above one. */
export function megabytes(mb: number): string {
	const units = ['MB', 'GB', 'TB', 'PB'];
	let value = mb;
	let unit = 0;
	while (value >= 1024 && unit < units.length - 1) {
		value /= 1024;
		unit += 1;
	}
	return `${number(value, value < 10 ? 1 : 0)} ${units[unit]}`;
}

/** A gibibyte: what a quota is typed in, and sent as bytes. */
export const GIB = 1024 ** 3;

/** A size in bytes. */
export function bytes(b: number): string {
	return b < 1024 * 1024 ? `${number(b / 1024, 0)} KB` : megabytes(b / (1024 * 1024));
}

/**
 * A duration, in the one largest unit that fits: `3 h`, `12 d`.
 *
 * `days`: the quantity is only known to the day — a drill counted in whole days — and
 * saying `0 s` would read as "just now" when it may date from last night.
 */
export function duration(seconds: number, resolution: 'seconds' | 'days' = 'seconds'): string {
	if (seconds < 0) return m.duration_in_the_future();
	if (resolution === 'days' || seconds >= 86_400) {
		const days = Math.floor(seconds / 86_400);
		if (days >= 60) return m.duration_months({ n: number(Math.floor(days / 30)) });
		return m.duration_days({ n: number(days) });
	}
	if (seconds >= 3_600) return m.duration_hours({ n: number(Math.floor(seconds / 3_600)) });
	if (seconds >= 60) return m.duration_minutes({ n: number(Math.floor(seconds / 60)) });
	return m.duration_seconds({ n: number(seconds) });
}

/** How long ago a timestamp in milliseconds was. */
export function since(ms: number, now = Date.now()): string {
	return duration(Math.max(0, Math.round((now - ms) / 1000)));
}

/**
 * The moment a server value names: seconds since the epoch, RFC 3339, or SQLite's
 * `datetime('now')`.
 *
 * ⚠️ SQLite writes UTC with no zone (`2026-10-21 14:03:00`), and `new Date` reads a
 * zone-less date-time as LOCAL time: every audit entry, run and announcement was shifted
 * by the reader's offset, and disagreed with the timeline, whose seconds are UTC.
 */
export function moment(value: string | number): Date {
	if (typeof value === 'number') return new Date(value * 1000);
	const zoneless = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)$/.exec(value);
	return new Date(zoneless ? `${zoneless[1]}T${zoneless[2]}Z` : value);
}

/** A date the server wrote, as this language writes a date and time. */
export function when(value: string | number): string {
	const date = moment(value);
	if (Number.isNaN(date.getTime())) return String(value);
	return new Intl.DateTimeFormat(getLocale(), { dateStyle: 'medium', timeStyle: 'short' }).format(
		date
	);
}

/**
 * How many calendar days, on this machine's calendar, separate a moment from now: `0`
 * today, `1` yesterday.
 *
 * Counted on the dates, not by dividing milliseconds: the night clocks go forward is a
 * 23-hour day, and a division rounded down called the day before it "yesterday".
 */
export function daysAgo(seconds: number, now = Date.now()): number {
	const date = (d: Date) => Date.UTC(d.getFullYear(), d.getMonth(), d.getDate());
	return Math.round((date(new Date(now)) - date(new Date(seconds * 1000))) / 86_400_000);
}

/** A moment of the day the home's curves cover, as this language writes an hour. */
export function clock(seconds: number): string {
	return new Intl.DateTimeFormat(getLocale(), { weekday: 'short', hour: '2-digit', minute: '2-digit' }).format(
		new Date(seconds * 1000)
	);
}

/** A throughput in bytes per second. */
export function rate(bytesPerSecond: number): string {
	return `${bytes(bytesPerSecond)}/s`;
}

/** A day the server wrote (`2026-10-10`), as this language writes a short date. */
export function day(value: string): string {
	const date = new Date(`${value}T12:00:00`);
	if (Number.isNaN(date.getTime())) return value;
	return new Intl.DateTimeFormat(getLocale(), { day: 'numeric', month: 'short' }).format(date);
}
