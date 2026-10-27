<script lang="ts">
	import { percent } from '#lib/format.ts';
	import { histories, historyOf, lineOf } from '#lib/home/history.svelte.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Disk from '#lib/ui/Disk.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Sparkline from '#lib/ui/Sparkline.svelte';

	const nodes = read('/api/nodes');
	const all = $derived(histories());
	$effect(() => all.watch());
	const past = $derived(historyOf(all.data, 'disk'));
</script>

<!-- Each disk of each machine, coloured by the server's pressure step, and how fast it
     filled over the period. -->
<Card fill title={m.widget_disks()} href="/nodes">
	<Loaded resource={nodes} empty={m.widget_nodes_none()}>
		{#snippet children(list)}
			<div class="grid grid-cols-[repeat(auto-fill,minmax(12rem,1fr))] gap-x-4 gap-y-3">
				{#each list as node (node.address)}
					{@const name = node.hostname ?? node.address}
					<section class="min-w-0">
						<h3 class="mb-1 truncate text-xs font-medium"><a href="/nodes/{encodeURIComponent(node.address)}" class="hover:text-accent hover:underline">{name}</a></h3>
						{#if node.reachable}
							<div class="space-y-2">
								{#each node.disks as disk (disk.path)}
									{@const line = lineOf(past, node.address, disk.path)}
									<div>
										<Disk {disk} />
										{#if past !== undefined && line !== undefined && line.points.length > 1}
											<div class="mt-1">
												<Sparkline lines={[{ points: line.points, name: disk.path }]} from={past.from} to={past.now} step={past.step_s} max={1} format={percent} label={m.widget_disk_curve({ name, disk: disk.path })} height={24} />
											</div>
										{/if}
									</div>
								{/each}
							</div>
						{:else}
							<p class="text-xs text-muted-text">{m.widget_unreachable()}</p>
						{/if}
					</section>
				{/each}
			</div>
		{/snippet}
	</Loaded>
</Card>
