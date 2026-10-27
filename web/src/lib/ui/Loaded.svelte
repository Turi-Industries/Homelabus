<script lang="ts" generics="T">
	import type { Snippet } from 'svelte';
	import { since } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import type { Resource } from '#lib/resource.svelte.ts';
	import { clock } from './clock.svelte.ts';
	import Gone from './Gone.svelte';

	/**
	 * The one place the loading, failed and stale states are worded — every page goes
	 * through it, so they are said the same way everywhere.
	 */
	let {
		resource,
		children,
		empty,
		back = '/'
	}: {
		resource: Resource<T>;
		children: Snippet<[T]>;
		/** Shown instead of `children` when the data is an empty list. */
		empty?: string;
		/** Where a detail naming nothing that exists sends the person: its list. */
		back?: string;
	} = $props();

	$effect(() => resource.watch());

	const isEmpty = $derived(
		empty !== undefined && Array.isArray(resource.data) && resource.data.length === 0
	);
</script>

<!-- A 404 is a verdict, not a moment: retrying asks the same question and gets the same
     answer, and after a removal the last known data describes something gone. -->
{#if resource.status === 404}
	<Gone {back} />
{:else if resource.data === undefined}
	{#if resource.error === undefined}
		<p class="py-6 text-sm text-muted-text" aria-busy="true">{m.state_loading()}</p>
	{:else}
		<div role="alert" class="flex flex-wrap items-center gap-3 rounded-lg border border-critical p-4 text-critical">
			<p class="min-w-0 grow basis-48 text-sm">{m.state_never_received({ error: resource.error })}</p>
			<button
				type="button"
				class="rounded-md border border-border px-3 py-1 text-sm text-text hover:bg-raised-surface"
				onclick={() => resource.refresh()}>{m.state_retry()}</button
			>
		</div>
	{/if}
{:else}
	{#if resource.error !== undefined && resource.received !== undefined}
		<!-- 🔴 The last known state, said to be one: shown as current it would be a lie. -->
		<p role="alert" class="mb-4 rounded-lg border border-critical p-3 text-sm font-medium text-critical">
			{m.state_stale({ age: since(resource.received, clock.now), error: resource.error })}
		</p>
	{/if}
	{#if isEmpty}
		<p class="py-6 text-sm text-muted-text">{empty}</p>
	{:else}
		{@render children(resource.data)}
	{/if}
{/if}
