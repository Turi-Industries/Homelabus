<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Source from '#lib/ui/Source.svelte';
	import StatusBoard from '#lib/ui/StatusBoard.svelte';

	/**
	 * The status page outside the console: for a signed-in person, `/api/status`; for
	 * anyone else, `/status`, which answers only when the installation published it.
	 * ⚠️ Not at `/status` itself: that path is the server's JSON, and a screen there
	 * could not be reloaded.
	 */
	const signedIn = read('/api/status');
	const published = read('/status');
	const anonymous = $derived(signedIn.status === 401);
	const brand = read('/api/appearance');
	$effect(() => brand.watch());
</script>

<svelte:head><title>{m.status_title()}</title></svelte:head>

<main class="mx-auto w-full max-w-3xl px-4 py-8">
	<h1 class="mb-6 text-2xl font-semibold">{brand.data?.name ?? ''} · {m.status_title()}</h1>
	{#if !anonymous}
		<Loaded resource={signedIn}>{#snippet children(page)}<StatusBoard {page} />{/snippet}</Loaded>
	{:else if published.status === 401 || published.status === 403 || published.status === 404}
		<p class="text-muted-text">{m.uptime_private()}</p>
		<a href="/auth/signin?return_to=%2Fuptime" class="mt-4 inline-block text-accent hover:underline">{m.state_sign_in()}</a>
	{:else}
		<Loaded resource={published}>{#snippet children(page)}<StatusBoard {page} />{/snippet}</Loaded>
	{/if}
	<div class="mt-8"><Source /></div>
</main>
