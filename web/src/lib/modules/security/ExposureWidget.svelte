<script lang="ts">
	import ExternalLink from '@lucide/svelte/icons/external-link';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';

	const exposure = read('/api/exposure');
</script>

<Card fill title={m.widget_exposure()} href="/exposure">
	<Loaded resource={exposure}>
		{#snippet children(rows)}
			{@const open = rows.filter((r) => r.public)}
			{#if open.length === 0}<p class="text-sm text-muted-text">{m.widget_exposure_none()}</p>{/if}
			<ul class="space-y-1.5">
				{#each open as r (r.host)}
					<li class="flex items-center gap-2 text-sm">
						<a href="https://{r.host}" target="_blank" rel="noreferrer" class="flex min-w-0 grow items-center gap-1.5 hover:text-accent">
							<ExternalLink aria-hidden="true" class="size-3.5 shrink-0 text-muted-text" /><span class="truncate">{r.host}</span>
						</a>
						<span class="shrink-0 text-xs text-muted-text">{r.app}</span>
					</li>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
