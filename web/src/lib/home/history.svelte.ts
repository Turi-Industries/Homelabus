import { page } from '$app/state';
import type { Schemas } from '#lib/api/client.ts';
import { read } from '#lib/resource.svelte.ts';

export type Window = Schemas['Window'];
export type Metric = Schemas['Metric'];
export type History = Schemas['History'];
export type Line = Schemas['HistoryLine'];

/** The periods a curve covers, shortest first. */
export const WINDOWS: readonly Window[] = ['hour', 'six_hours', 'day'];

/**
 * The period every curve on the home shows: ONE choice above them all, so the numbers on
 * screen always cover the same hours. In the address, like a list's filters: it
 * survives a reload and Back.
 */
export function shownWindow(): Window {
	const asked = page.url.searchParams.get('window');
	return WINDOWS.find((w) => w === asked) ?? 'day';
}

/** Every measurement's history over the period shown: one request, shared by every card. */
export function histories() {
	return read('/api/history', { query: { window: shownWindow() } });
}

/** The history of one measurement, out of `histories()`'s answer. */
export function historyOf(all: History[] | undefined, metric: Metric): History | undefined {
	return all?.find((h) => h.metric === metric);
}

/** The curve of one machine, or one of its disks, if it has one. */
export function lineOf(h: History | undefined, subject: string, disk: string | null = null): Line | undefined {
	return h?.lines.find((l) => l.subject === subject && l.disk === disk);
}
