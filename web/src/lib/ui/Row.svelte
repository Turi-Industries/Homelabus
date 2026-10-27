<script lang="ts">
	import type { Snippet } from 'svelte';

	/**
	 * One line of a list: what it is on the left, its state on the right — stacked when
	 * the two do not share a line, never widening the page. A row with a destination is a
	 * link; a row carrying a button is not also a click target.
	 */
	let {
		href,
		children,
		aside
	}: { href?: string; children: Snippet; aside?: Snippet } = $props();
</script>

{#snippet body()}
	<div class="min-w-0 grow basis-48">{@render children()}</div>
	{#if aside}<div class="flex shrink-0 flex-wrap items-center gap-2">{@render aside()}</div>{/if}
{/snippet}

<li class="border-b border-border last:border-b-0">
	{#if href !== undefined}
		<a {href} class="-mx-2 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-md px-2 py-2.5 hover:bg-raised-surface">
			{@render body()}
		</a>
	{:else}
		<div class="flex flex-wrap items-center gap-x-4 gap-y-1 py-2.5">{@render body()}</div>
	{/if}
</li>
