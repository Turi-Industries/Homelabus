<script lang="ts">
	import { clock } from '#lib/format.ts';

	type Point = [number, number];

	/**
	 * A curve over the period the home shows: a 2 px line, a wash under the first one,
	 * and a crosshair that reads every line at the moment pointed at — by the pointer,
	 * or by the arrow keys once it has the focus.
	 *
	 * 🔴 A gap in time is a gap in the line. A machine that did not answer for an hour
	 * has no measurement for it, and a line drawn across says it idled at the average of
	 * both ends.
	 */
	let {
		lines,
		from,
		to,
		step,
		max,
		format,
		label,
		height = 36,
		quiet = false
	}: {
		/** The first is the one washed underneath; a second is drawn in the muted ink. */
		lines: { points: Point[]; name: string }[];
		/** The period, in Unix seconds. */
		from: number;
		to: number;
		/** Seconds between two points: a longer silence is a gap. */
		step: number;
		/** The top of the scale; the highest value when left out. */
		max?: number;
		format: (value: number) => string;
		/** What the curve is, for whoever does not see it. */
		label: string;
		height?: number;
		/** A trend inside something already focusable — a figure that is a link: drawn
		 * only, with no focus and no readout of its own, and its words left to the link. */
		quiet?: boolean;
	} = $props();

	let width = $state(0);
	let at = $state<number | undefined>();
	let chart = $state<HTMLElement>();
	// Where the chart is on screen when it is read: the readout is placed against the
	// window, since a tile that scrolls would clip it above its first curve.
	let box = $state<DOMRect | undefined>();

	// Left out, the scale is the highest value with a tenth to spare — and 1 when nothing
	// moved at all, so a flat zero is drawn on the floor rather than dividing by it.
	const top = $derived(max ?? (Math.max(...lines.flatMap((l) => l.points.map(([, v]) => v)), 0) * 1.1 || 1));
	const x = (t: number) => ((t - from) / Math.max(1, to - from)) * width;
	// 2 px of room so a line at the top or bottom is not cut in half.
	const y = (v: number) => 2 + (1 - Math.min(Math.max(v / top, 0), 1)) * (height - 4);

	/** The line as runs of points with no gap between them. */
	function runs(points: Point[]): Point[][] {
		// A silence is a gap when it is longer than the line's own rhythm: the step asked
		// for, or the usual spacing of its measurements when they are rarer than that —
		// measured every five minutes, a six-hour curve is otherwise all dots.
		const spacings = points.slice(1).map(([t], i) => t - (points[i]?.[0] ?? t)).sort((a, b) => a - b);
		const usual = spacings[Math.floor(spacings.length / 2)] ?? step;
		const gap = Math.max(step, usual) * 1.5;
		const out: Point[][] = [];
		for (const p of points) {
			const run = out[out.length - 1];
			const last = run?.[run.length - 1];
			if (run !== undefined && last !== undefined && p[0] - last[0] <= gap) run.push(p);
			else out.push([p]);
		}
		return out;
	}
	const path = (run: Point[]) => run.map(([t, v], i) => `${i === 0 ? 'M' : 'L'}${x(t).toFixed(1)},${y(v).toFixed(1)}`).join('');
	const area = (run: Point[]) => {
		const first = run[0];
		const last = run[run.length - 1];
		if (first === undefined || last === undefined) return '';
		return `${path(run)}L${x(last[0]).toFixed(1)},${height}L${x(first[0]).toFixed(1)},${height}Z`;
	};

	// Every moment any line was measured: what the crosshair snaps to.
	const moments = $derived([...new Set(lines.flatMap((l) => l.points.map(([t]) => t)))].sort((a, b) => a - b));
	const nearest = (t: number) => moments.reduce((best, m) => (Math.abs(m - t) < Math.abs(best - t) ? m : best), moments[0] ?? t);
	const valueAt = (points: Point[], t: number) => points.find(([pt]) => pt === t)?.[1];

	function point(e: PointerEvent) {
		box = chart?.getBoundingClientRect();
		if (box === undefined) return;
		at = nearest(from + ((e.clientX - box.left) / box.width) * (to - from));
	}

	function keys(e: KeyboardEvent) {
		if (moments.length === 0) return;
		box = chart?.getBoundingClientRect();
		const i = at === undefined ? moments.length - 1 : moments.indexOf(at);
		if (e.key === 'ArrowLeft') at = moments[Math.max(0, i - 1)];
		else if (e.key === 'ArrowRight') at = moments[Math.min(moments.length - 1, i + 1)];
		else if (e.key === 'Home') at = moments[0];
		else if (e.key === 'End') at = moments[moments.length - 1];
		else if (e.key === 'Escape') at = undefined;
		else return;
		e.preventDefault();
	}

	// Said in words for a screen reader: the latest value of each line, and its range.
	const summary = $derived(
		lines
			.filter((l) => l.points.length > 0)
			.map((l) => {
				const values = l.points.map(([, v]) => v);
				const latest = values[values.length - 1] ?? 0;
				return `${l.name} ${format(latest)} (${format(Math.min(...values))} – ${format(Math.max(...values))})`;
			})
			.join(', ')
	);
	const tipLeft = $derived(at === undefined || box === undefined ? 0 : box.left + Math.min(Math.max(x(at), 60), Math.max(60, width - 60)));
</script>

<!-- An image, focusable: its words already say every line's latest value and range,
     and the keys only move the readout over what it says. -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
<div
	bind:this={chart}
	class="relative rounded-sm outline-offset-2"
	style:height="{height}px"
	bind:clientWidth={width}
	role={quiet ? undefined : 'img'}
	aria-label={quiet ? undefined : `${label}: ${summary}`}
	aria-hidden={quiet ? 'true' : undefined}
	tabindex={quiet ? undefined : 0}
	onpointermove={quiet ? undefined : point}
	onpointerleave={() => (at = undefined)}
	onkeydown={quiet ? undefined : keys}
	onblur={() => (at = undefined)}
>
	{#if width > 0}
		<svg {width} {height} class="block overflow-visible" aria-hidden="true">
			{#each runs(lines[0]?.points ?? []) as run, i (i)}
				<path d={area(run)} class="fill-accent/10" />
			{/each}
			{#each lines as line, n (n)}
				{#each runs(line.points) as run, i (i)}
					{#if run.length === 1}
						<circle cx={x(run[0]?.[0] ?? 0)} cy={y(run[0]?.[1] ?? 0)} r="1.5" class={n === 0 ? 'fill-accent' : 'fill-muted-text'} />
					{:else}
						<path d={path(run)} fill="none" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" class={n === 0 ? 'stroke-accent' : 'stroke-muted-text'} />
					{/if}
				{/each}
			{/each}
			{#if at !== undefined}
				<line x1={x(at)} x2={x(at)} y1="0" y2={height} stroke-width="1" class="stroke-border" />
			{/if}
		</svg>
	{/if}
	{#if at !== undefined && box !== undefined}
		<!-- The value leads, the name follows; a short stroke keys each line. -->
		<div
			class="pointer-events-none fixed z-50 -translate-x-1/2 -translate-y-full rounded-md border border-border bg-raised-surface px-2 py-1 text-xs whitespace-nowrap shadow-sm"
			style:left="{tipLeft}px"
			style:top="{box.top - 4}px"
		>
			<p class="text-muted-text">{clock(at)}</p>
			{#each lines as line, n (n)}
				{@const v = valueAt(line.points, at)}
				<p class="flex items-center gap-1.5">
					<span aria-hidden="true" class={['h-0.5 w-2.5 rounded-full', n === 0 ? 'bg-accent' : 'bg-muted-text']}></span>
					<span class="font-semibold tabular-nums">{v === undefined ? '—' : format(v)}</span>
					{#if lines.length > 1}<span class="text-muted-text">{line.name}</span>{/if}
				</p>
			{/each}
		</div>
	{/if}
</div>
