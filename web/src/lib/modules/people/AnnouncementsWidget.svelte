<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';

	const announcements = read('/api/announcements');
</script>

<Card fill title={m.widget_announcements()} href="/me">
	<Loaded resource={announcements}>
		{#snippet children(list)}
			{@const active = list.filter((a) => a.active)}
			{#if active.length === 0}
				<p class="text-sm text-muted-text">{m.widget_announcements_none()}</p>
			{/if}
			<ul class="space-y-3">
				{#each active.slice(0, 4) as a (a.id)}
					<li>
						<div class="flex flex-wrap items-center justify-between gap-2">
							<span class="min-w-0 text-sm font-medium">{a.title}</span><Mark attention={a.attention} />
						</div>
						<p class="mt-0.5 line-clamp-2 text-sm text-muted-text">{a.body}</p>
					</li>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
