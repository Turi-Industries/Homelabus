<script lang="ts">
	import { allowed } from '#lib/api/rights.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { me } from '#lib/session.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { widgets, type HomeWidget } from '#lib/widgets.ts';

	/**
	 * A wall display: no navigation, no action, nothing to click into.
	 *
	 * 🔴 An ALLOWLIST. A wall is seen by anyone in the room: what will be sensitive
	 * tomorrow cannot be enumerated, what is harmless today can. A card added to the
	 * home later is NOT on the wall until someone puts it here.
	 */
	const KIOSK: HomeWidget[] = ['uptime', 'nodes', 'apps', 'resilience'];
	const who = me();
</script>

<svelte:head><title>{m.kiosk_title()}</title></svelte:head>

<main class="min-h-dvh p-6">
	<h1 class="sr-only">{m.kiosk_title()}</h1>
	<Loaded resource={who}>
		{#snippet children(person)}
			<!-- `inert`, not `pointer-events-none`: that stops the pointer and leaves Tab and
			     Enter to follow a card's link into the console. -->
			<div inert class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
				{#each KIOSK.filter((w) => allowed(person.can, widgets[w].reads, 'GET')) as card (card)}
					{@const Widget = widgets[card].component}
					<Widget />
				{/each}
			</div>
		{/snippet}
	</Loaded>
</main>
