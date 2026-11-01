<script lang="ts">
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Disk from '#lib/ui/Disk.svelte';
	import Gauge from '#lib/ui/Gauge.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { code, muted } from '#lib/ui/styles.ts';
	import { nodeProblem } from '#lib/words.ts';

	const nodes = read('/api/nodes');
</script>

<Loaded resource={nodes}>
	{#snippet children(list)}
		{#if list.length === 0}
			<p class={muted}>{m.nodes_no_agent_reporting()}</p>
			<code class="mt-2 block {code}">{m.nodes_add_node_command()}</code>
		{/if}
		<p class="mb-4 {muted}">
			{m.nodes_node_count_with_unreachable({ count: list.length, unreachable: list.filter((n) => !n.reachable).length })}
		</p>
		<div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
			{#each list as node (node.address)}
				<Card title={node.hostname ?? node.address} href="/nodes/{encodeURIComponent(node.address)}">
					{#if node.problem !== null}
						<p class="mb-3 text-sm text-critical">{nodeProblem(node.problem)}{node.detail ? ` — ${node.detail}` : ''}</p>
					{/if}
					{#if node.reachable}
						<div class="grid grid-cols-2 gap-3">
							{#if node.cpu_busy !== null}<Gauge label={m.nodes_cpu()} value={node.cpu_busy} />{/if}
							{#if node.memory_used !== null}<Gauge label={m.nodes_memory()} value={node.memory_used} />{/if}
							{#if node.swap_used !== null}<Gauge label={m.nodes_swap()} value={node.swap_used} />{/if}
						</div>
						<div class="mt-3 space-y-2">
							{#each node.disks as disk (disk.path)}<Disk {disk} />{/each}
						</div>
					{/if}
					<p class="mt-3 text-sm">{node.protection === null ? m.nodes_protection_never_read() : m.nodes_protection({ level: node.protection })}</p>
					<p class="mt-1 text-xs text-muted-text">
						{node.address}
						{#if node.report_age_s !== null}· {m.nodes_last_report({ age: duration(node.report_age_s) })}{/if}
						{#if node.agent_version !== null}· {m.nodes_agent_version({ version: node.agent_version })}{/if}
					</p>
				</Card>
			{/each}
		</div>
	{/snippet}
</Loaded>
