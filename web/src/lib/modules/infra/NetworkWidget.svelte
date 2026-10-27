<script lang="ts">
	import { rate } from '#lib/format.ts';
	import { histories, historyOf, lineOf } from '#lib/home/history.svelte.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Sparkline from '#lib/ui/Sparkline.svelte';

	const nodes = read('/api/nodes');
	const all = $derived(histories());
	$effect(() => all.watch());
	const received = $derived(historyOf(all.data, 'net_in'));
	const sent = $derived(historyOf(all.data, 'net_out'));

	const latest = (points: [number, number][] | undefined) => points?.[points.length - 1]?.[1];
</script>

<!-- What each machine receives (washed) and sends (muted), on one scale per machine. -->
<Card fill title={m.widget_network()} href="/nodes">
	<Loaded resource={nodes} empty={m.widget_nodes_none()}>
		{#snippet children(list)}
			<div class="grid grid-cols-[repeat(auto-fill,minmax(14rem,1fr))] gap-x-4 gap-y-3">
				{#each list as node (node.address)}
					{@const name = node.hostname ?? node.address}
					{@const into = lineOf(received, node.address)}
					{@const out = lineOf(sent, node.address)}
					<section class="min-w-0">
						<h3 class="flex flex-wrap items-baseline justify-between gap-x-2 text-xs">
							<a href="/nodes/{encodeURIComponent(node.address)}" class="truncate font-medium hover:text-accent hover:underline">{name}</a>
							{#if node.reachable && (latest(into?.points) !== undefined || latest(out?.points) !== undefined)}
								<span class="flex gap-2 text-muted-text tabular-nums">
									<span class="flex items-center gap-1"><span aria-hidden="true" class="h-0.5 w-2.5 rounded-full bg-accent"></span>↓ {rate(latest(into?.points) ?? 0)}</span>
									<span class="flex items-center gap-1"><span aria-hidden="true" class="h-0.5 w-2.5 rounded-full bg-muted-text"></span>↑ {rate(latest(out?.points) ?? 0)}</span>
								</span>
							{/if}
						</h3>
						{#if !node.reachable}
							<p class="text-xs text-muted-text">{m.widget_unreachable()}</p>
						{:else if received !== undefined && into !== undefined && into.points.length > 1}
							<div class="mt-1">
								<Sparkline
									lines={[{ points: into.points, name: m.widget_received() }, ...(out ? [{ points: out.points, name: m.widget_sent() }] : [])]}
									from={received.from}
									to={received.now}
									step={received.step_s}
									format={rate}
									label={m.widget_network_curve({ name })}
								/>
							</div>
						{:else}
							<p class="text-xs text-muted-text">{m.widget_history_collecting()}</p>
						{/if}
					</section>
				{/each}
			</div>
		{/snippet}
	</Loaded>
</Card>
