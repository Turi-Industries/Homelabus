<script lang="ts">
	import { widgets, type HomeTile } from '#lib/widgets.ts';
	import { columns, pack } from './layout.ts';

	/**
	 * The home's tiles on a grid as tall as the screen: every cell covered, nothing to
	 * scroll on a computer or a tablet. On a phone the tiles stack, each as tall as it
	 * needs up to a cap, and what is longer scrolls inside it.
	 */
	let { tiles }: { tiles: HomeTile[] } = $props();

	/** The shortest a row may be: a figure, its caption and its bar. */
	const ROW_MIN = '9rem';
	/** Between two tiles: `gap-3`. */
	const GAP = '0.75rem';
	/** What `main` keeps below the grid. */
	const BELOW = 24;

	let grid = $state<HTMLElement>();
	let width = $state(0);
	let tall = $state<number | undefined>();
	const cols = $derived(columns(width));
	const stacked = $derived(cols === 1);
	const layout = $derived(pack(tiles, cols));

	// A HEIGHT, not a minimum: under a minimum the rows grow to hold what their tiles
	// list, and twenty-one problems pushed the home to three screens. Fixed, a long list
	// scrolls inside its tile. Never shorter than the rows' minimum, so a home of many
	// tiles on a short screen scrolls rather than crushing them.
	//
	// The height left under the grid's top. Measured, not computed from the header's
	// height: the header wraps, and the "unreachable" badge can join it.
	function measure() {
		if (grid === undefined) return;
		tall = Math.max(0, window.innerHeight - (grid.getBoundingClientRect().top + window.scrollY) - BELOW);
	}
	$effect(() => {
		measure();
		window.addEventListener('resize', measure);
		return () => window.removeEventListener('resize', measure);
	});
</script>

<div
	bind:this={grid}
	bind:clientWidth={width}
	class="grid gap-3"
	style:grid-template-columns="repeat({cols}, minmax(0, 1fr))"
	style:grid-template-rows={stacked ? undefined : `repeat(${layout.rows}, minmax(${ROW_MIN}, 1fr))`}
	style:height={stacked || tall === undefined ? undefined : `max(${tall}px, ${layout.rows} * ${ROW_MIN} + ${layout.rows - 1} * ${GAP})`}
>
	{#each tiles as tile, i (tile.widget)}
		{@const place = layout.placed[i]}
		{@const Widget = widgets[tile.widget].component}
		<div
			class={['flex min-h-0 min-w-0 flex-col', stacked && 'max-h-[32rem]']}
			style:grid-column={stacked || place === undefined ? undefined : `${place.x + 1} / span ${place.w}`}
			style:grid-row={stacked || place === undefined ? undefined : `${place.y + 1} / span ${place.h}`}
		>
			<Widget />
		</div>
	{/each}
</div>
