<script lang="ts">
	import type { Snippet } from 'svelte';
	import { read } from '#lib/resource.svelte.ts';
	import { reasons } from '#lib/causes.ts';
	import { tone } from '#lib/words.ts';

	/**
	 * The head of a detail page: what it is, what is wrong with it — the inbox's own
	 * causes naming it, never a generic "action required" — and what can be done to it,
	 * right there. An action in a card at the bottom of the page is an action not seen.
	 */
	let {
		title,
		subject = title,
		meta,
		actions
	}: {
		title: string;
		/** The name the inbox's causes cover it by, when it differs from the title. */
		subject?: string;
		meta?: Snippet;
		actions?: Snippet;
	} = $props();

	const issues = read('/api/issues');
	$effect(() => issues.watch());
	const wrong = $derived(reasons(issues.data ?? [], subject));
</script>

<header class="mb-6 flex flex-wrap items-center gap-x-4 gap-y-2">
	<h2 class="text-lg font-semibold">{title}</h2>
	{#each wrong as r (r.text)}
		<span class={['inline-flex items-center gap-1.5 text-sm', tone[r.attention].text]}>
			<span aria-hidden="true" class={['size-2 rounded-full', tone[r.attention].bg]}></span>{r.text}
		</span>
	{/each}
	{#if meta}<span class="text-sm text-muted-text">{@render meta()}</span>{/if}
	{#if actions}<div class="ml-auto flex flex-wrap items-center gap-2">{@render actions()}</div>{/if}
</header>
