<script lang="ts">
	import { number, percent } from '#lib/format.ts';
	import { histories, historyOf, lineOf } from '#lib/home/history.svelte.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Gauge from '#lib/ui/Gauge.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Sparkline from '#lib/ui/Sparkline.svelte';

	const nodes = read('/api/nodes');
	const all = $derived(histories());
	$effect(() => all.watch());
	const past = $derived(historyOf(all.data, 'cpu'));
</script>

<Card fill title={m.widget_cpu()} href="/nodes">
	<Loaded resource={nodes} empty={m.widget_nodes_none()}>
		{#snippet children(list)}
			<ul class="space-y-3">
				{#each list as node (node.address)}
					{@const name = node.hostname ?? node.address}
					<li>
						<!-- 🔴 An unreachable machine has no numbers, not bad ones: a bar at zero
						     would read as a machine at rest. -->
						{#if node.reachable && node.cpu_busy !== null}
							<Gauge label={name} href="/nodes/{encodeURIComponent(node.address)}" value={node.cpu_busy} />
							{@const line = lineOf(past, node.address)}
							{#if past !== undefined && line !== undefined && line.points.length > 1}
								<div class="mt-1">
									<Sparkline lines={[{ points: line.points, name }]} from={past.from} to={past.now} step={past.step_s} max={1} format={percent} label={m.widget_cpu_curve({ name })} />
								</div>
							{/if}
							{#if node.load_per_core !== null}
								<p class="mt-0.5 text-xs text-muted-text">{m.widget_load({ load: number(node.load_per_core, 2) })}</p>
							{/if}
						{:else}
							<!-- Reachable with no figure: the agent's first reading, which needs two
							     reads of the processor's counters to give one. -->
							<p class="flex justify-between gap-2 text-xs text-muted-text"><span class="truncate">{name}</span><span>{node.reachable ? m.widget_first_reading() : m.widget_unreachable()}</span></p>
						{/if}
					</li>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
