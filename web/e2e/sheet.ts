import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { FullConfig } from '@playwright/test';

/** Where the sheet is written: beside the build, ignored by git. */
export const OUT = join('..', 'target', 'shots');
/** The run before this one, kept so a change can be looked at beside what it replaced. */
const BEFORE = join('..', 'target', 'shots-before');

/** One photograph. */
export interface Shot {
	theme: string;
	locale: string;
	width: 'wide' | 'narrow';
	file: string;
	/** How many screens of its width the page is tall — 1 is a page read without scrolling. */
	screens: number;
}

/** What one controller's run wrote: `<project>.json` beside the images. */
export interface Run {
	data: string;
	themes: string[];
	locales: string[];
	screens: { screen: string; url: string; shots: Shot[] }[];
}

function escape(text: string): string {
	return text.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] ?? c);
}

/** A choice of which shots to show — every value the runs produced, walked. */
function filter(name: string, values: string[]): string {
	const options = values.map((v) => `<option>${escape(v)}</option>`).join('');
	return `<label>${name} <select data-filter="${name}"><option value="">all</option>${options}</select></label>`;
}

/**
 * `target/shots/index.html`: one section per screen, its shots side by side, filters
 * on top. Built from what the runs wrote, so a screen added tomorrow is on it without
 * this file changing.
 */
function sheet(runs: Run[]): string {
	const order = [...new Set(runs.flatMap((r) => r.screens.map((s) => s.screen)))].sort();
	const values = (pick: (r: Run) => string[]) => [...new Set(runs.flatMap(pick))];
	const sections = order.map((screen) => {
		const figures = runs.flatMap((run) =>
			(run.screens.find((s) => s.screen === screen)?.shots ?? []).map((shot) => {
				const tags = { data: run.data, theme: shot.theme, locale: shot.locale, width: shot.width };
				const attributes = Object.entries(tags).map(([k, v]) => `data-${k}="${escape(v)}"`).join(' ');
				return `<figure ${attributes} class="${shot.width}"><a href="${escape(shot.file)}"><img loading="lazy" src="${escape(shot.file)}" alt=""></a><figcaption>${escape([...Object.values(tags), `${shot.screens} screens`].join(' · '))}</figcaption></figure>`;
			})
		);
		return `<section><h2>${escape(screen)}</h2><div class="row">${figures.join('')}</div></section>`;
	});
	const total = runs.reduce((n, r) => n + r.screens.reduce((m, s) => m + s.shots.length, 0), 0);
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Contact sheet</title>
<style>
	:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
	body { margin: 0 16px 48px; }
	header { position: sticky; top: 0; padding: 12px 0; background: Canvas; display: flex; flex-wrap: wrap; gap: 16px; align-items: center; z-index: 1; }
	h2 { font-size: 1rem; margin: 32px 0 8px; font-family: ui-monospace, monospace; }
	.row { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-start; }
	figure { margin: 0; }
	figure img { display: block; height: 300px; object-fit: cover; object-position: top; border: 1px solid GrayText; }
	figure.wide img { width: 360px; }
	figure.narrow img { width: 101px; }
	figcaption { font-size: 0.75rem; color: GrayText; max-width: 360px; }
	figure.narrow figcaption { max-width: 101px; overflow-wrap: anywhere; }
	[hidden] { display: none; }
</style></head><body>
<header><strong>${order.length} screens, ${total} shots</strong>
${filter('data', values((r) => [r.data]))}
${filter('theme', values((r) => r.themes))}
${filter('locale', values((r) => r.locales))}
${filter('width', values((r) => r.screens.flatMap((s) => s.shots.map((shot) => shot.width))))}
</header>
${sections.join('\n')}
<script>
	const selects = [...document.querySelectorAll('[data-filter]')];
	function apply() {
		for (const f of document.querySelectorAll('figure')) {
			f.hidden = selects.some((s) => s.value !== '' && f.dataset[s.dataset.filter] !== s.value);
		}
	}
	for (const s of selects) s.addEventListener('change', apply);
</script>
</body></html>
`;
}

/** The runs a directory holds, one per project that finished. */
function runsIn(dir: string, config: FullConfig): Run[] {
	return config.projects.flatMap((project) => {
		const path = join(dir, `${project.name}.json`);
		return existsSync(path) ? [JSON.parse(readFileSync(path, 'utf8')) as Run] : [];
	});
}

/**
 * Playwright's global setup, and the teardown it returns. Before the run, last time's
 * images become the "before" — never mixed into this run's folder, where a screen since
 * removed would look current. After it, the page: this run, beside the one before.
 */
export default function setup(config: FullConfig) {
	rmSync(BEFORE, { recursive: true, force: true });
	if (existsSync(OUT)) renameSync(OUT, BEFORE);
	return () => {
		// The run before, filed as its own data and pointing at its own folder: the "data"
		// filter then shows a screen before and after a change, side by side.
		const before = runsIn(BEFORE, config).map((run) => ({
			...run,
			data: `${run.data} · before`,
			screens: run.screens.map((screen) => ({
				...screen,
				shots: screen.shots.map((shot) => ({ ...shot, file: join('..', 'shots-before', shot.file) }))
			}))
		}));
		const runs = [...before, ...runsIn(OUT, config)];
		if (runs.length === 0) return;
		writeFileSync(join(OUT, 'index.html'), sheet(runs));
		console.log(`contact sheet: ${join(OUT, 'index.html')}`);
	};
}
