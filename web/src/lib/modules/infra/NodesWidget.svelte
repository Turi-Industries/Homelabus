<script lang="ts">
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { tone } from '#lib/words.ts';

	const nodes = read('/api/nodes');
</script>

<!-- What each machine is: system, kernel, how long it has run, what it hosts. Its gauges
     are the processor, memory and disk cards'. -->
<Card fill title={m.widget_nodes()} href="/nodes">
	<Loaded resource={nodes} empty={m.widget_nodes_none()}>
		{#snippet children(list)}
			<ul class="divide-y divide-border">
				{#each list as node (node.address)}
					<li class="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 py-1.5 text-sm">
						<span aria-hidden="true" class={['size-2 shrink-0 self-center rounded-full', node.reachable ? tone.ok.bg : 'bg-muted-text']}></span>
						<a href="/nodes/{encodeURIComponent(node.address)}" class="min-w-0 grow basis-32 truncate font-medium hover:underline">{node.hostname ?? node.address}</a>
						{#if node.reachable}
							<span class="text-xs text-muted-text">{[node.distro, node.kernel].filter((x) => x !== null).join(' · ')}</span>
							{#if node.uptime_s !== null}<span class="text-xs text-muted-text">{m.widget_up_for({ duration: duration(node.uptime_s) })}</span>{/if}
							<span class="text-xs text-muted-text">{m.widget_hosting({ count: node.tasks.length })}</span>
						{:else}
							<span class="text-xs text-muted-text">{m.widget_unreachable()}</span>
						{/if}
					</li>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
