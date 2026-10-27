<script lang="ts">
	import { percent } from '#lib/format.ts';
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
	const memory = $derived(historyOf(all.data, 'memory'));
	const swap = $derived(historyOf(all.data, 'swap'));
</script>

<Card fill title={m.widget_memory()} href="/nodes">
	<Loaded resource={nodes} empty={m.widget_nodes_none()}>
		{#snippet children(list)}
			<ul class="space-y-3">
				{#each list as node (node.address)}
					{@const name = node.hostname ?? node.address}
					<li>
						{#if node.reachable && node.memory_used !== null}
							<Gauge label={name} href="/nodes/{encodeURIComponent(node.address)}" value={node.memory_used} />
							{@const used = lineOf(memory, node.address)}
							{@const swapped = lineOf(swap, node.address)}
							{#if memory !== undefined && used !== undefined && used.points.length > 1}
								<!-- Memory washed, swap in the muted ink: one scale, both fractions. -->
								<div class="mt-1">
									<Sparkline
										lines={[{ points: used.points, name: m.nodes_memory() }, ...(swapped ? [{ points: swapped.points, name: m.nodes_swap() }] : [])]}
										from={memory.from}
										to={memory.now}
										step={memory.step_s}
										max={1}
										format={percent}
										label={m.widget_memory_curve({ name })}
									/>
								</div>
							{/if}
							{#if node.swap_used !== null}
								<p class="mt-0.5 text-xs text-muted-text">{m.widget_swap({ value: percent(node.swap_used) })}</p>
							{/if}
						{:else}
							<p class="flex justify-between gap-2 text-xs text-muted-text"><span class="truncate">{name}</span><span>{node.reachable ? m.widget_first_reading() : m.widget_unreachable()}</span></p>
						{/if}
					</li>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
