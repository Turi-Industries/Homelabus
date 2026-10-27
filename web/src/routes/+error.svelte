<script lang="ts">
	import { page } from '$app/state';
	import { m } from '#lib/paraglide/messages.js';

	// A URL no page answers: said so, with the way back — never a blank screen.
</script>

<svelte:head><title>{page.status === 404 ? m.state_not_found() : (page.error?.message ?? '')}</title></svelte:head>

<main class="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-4 p-6">
	<p class="text-lg font-semibold">{page.status === 404 ? m.state_not_found() : (page.error?.message ?? '')}</p>
	<a href="/" class="self-start text-accent hover:underline">{m.state_go_home()}</a>
</main>
