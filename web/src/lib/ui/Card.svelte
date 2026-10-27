<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		title,
		href,
		action,
		fill = false,
		children
	}: {
		title?: string;
		href?: string;
		action?: Snippet;
		/** A tile of the home: as tall as its cell, and what does not fit scrolls inside it
		 * rather than pushing the home past the screen. */
		fill?: boolean;
		children: Snippet;
	} = $props();
</script>

<section class={['flex min-w-0 flex-col rounded-lg border border-border bg-surface', fill ? 'h-full min-h-0 p-3' : 'p-4']}>
	{#if title !== undefined || action !== undefined}
		<header class={['flex flex-wrap items-center justify-between gap-2', fill ? 'mb-2' : 'mb-3']}>
			{#if title !== undefined}
				<h2 class="text-sm font-semibold">
					{#if href !== undefined}
						<a {href} class="hover:text-accent hover:underline">{title}</a>
					{:else}
						{title}
					{/if}
				</h2>
			{/if}
			{#if action}<div class="flex flex-wrap items-center gap-3">{@render action()}</div>{/if}
		</header>
	{/if}
	{#if fill}
		<!-- `relative`, or what is absolutely placed inside — a screen reader's words —
		     escapes the scrolling and lengthens the page. -->
		<div class="relative -mx-1 min-h-0 flex-1 overflow-y-auto px-1">{@render children()}</div>
	{:else}
		{@render children()}
	{/if}
</section>
