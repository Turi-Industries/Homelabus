<script lang="ts">
	import { percent } from '#lib/format.ts';

	/**
	 * A fraction as a bar. The colour is the caller's — each quantity has its own
	 * thresholds, decided by the server, and a gauge that picked its own would lie for
	 * whichever quantity it was not drawn for.
	 */
	let {
		label,
		value,
		tone = 'bg-accent',
		href
	}: { label: string; value: number; tone?: string; href?: string } = $props();
</script>

<div class="min-w-0">
	<div class="flex justify-between gap-2 text-xs text-muted-text">
		{#if href !== undefined}
			<a {href} class="min-w-0 truncate hover:text-accent hover:underline">{label}</a>
		{:else}
			<span class="min-w-0 truncate">{label}</span>
		{/if}
		<span class="tabular-nums">{percent(value)}</span>
	</div>
	<div class="mt-1 h-1.5 overflow-hidden rounded-full bg-raised-surface" role="presentation">
		<div class={['h-full rounded-full', tone]} style:width="{Math.min(100, Math.max(0, value * 100))}%"></div>
	</div>
</div>
