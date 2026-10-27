<script lang="ts">
	import { since } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import { clock } from '#lib/ui/clock.svelte.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { tone } from '#lib/words.ts';

	const timeline = read('/api/timeline');
</script>

<Card fill title={m.widget_activity()} href="/timeline">
	<Loaded resource={timeline} empty={m.widget_activity_none()}>
		{#snippet children(events)}
			<ol class="space-y-2">
				{#each events.slice(0, 6) as e, i (i)}
					<li class="flex gap-3 text-sm">
						<span aria-hidden="true" class={['mt-1.5 size-2 shrink-0 rounded-full', tone[e.attention].bg]}></span>
						<span class="min-w-0 flex-1"><span class="font-medium">{e.target}</span> — {e.what}</span>
						<span class="shrink-0 text-xs text-muted-text">{since(e.when * 1000, clock.now)}</span>
					</li>
				{/each}
			</ol>
		{/snippet}
	</Loaded>
</Card>
