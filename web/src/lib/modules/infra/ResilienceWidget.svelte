<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { topology } from '#lib/words.ts';

	const resilience = read('/api/topology');
</script>

<!-- How the cluster is built — machines, managers, failure domains — and the verdict in
     words. What it cannot survive is a line of the problems' card, not a bar here. -->
<Card fill title={m.widget_resilience()} href="/resilience">
	<Loaded resource={resilience}>
		{#snippet children(t)}
			{@const figures = [
				[t.total_nodes, m.widget_cluster_machines()],
				[t.managers.length, m.widget_cluster_managers()],
				[t.domains.length, m.widget_cluster_domains()]
			] as const}
			<ul class="flex flex-wrap gap-2">
				{#each figures as [value, caption] (caption)}
					<li class="flex min-w-0 grow basis-20 flex-col rounded-md bg-raised-surface px-3 py-1.5">
						<span class="text-xl font-semibold tabular-nums">{value}</span>
						<span class="truncate text-xs text-muted-text">{caption}</span>
					</li>
				{/each}
			</ul>
			<p class="mt-2 text-xs text-muted-text">{topology(t.verdict)}</p>
		{/snippet}
	</Loaded>
</Card>
