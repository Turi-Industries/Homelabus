<script lang="ts">
	import { page } from '$app/state';
	import { proposal, panel } from '#lib/action.svelte.ts';
	import { bytes, duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Disk from '#lib/ui/Disk.svelte';
	import Gauge from '#lib/ui/Gauge.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import { button, muted } from '#lib/ui/styles.ts';
	import { nodeProblem } from '#lib/words.ts';

	const address = $derived(page.params.address ?? '');
	const detail = $derived(read('/api/nodes/{address}/detail', { path: { address } }));

	const availability: Record<string, [() => string, () => string]> = {
		active: [m.node_detail_state_active, m.node_detail_active_explanation],
		drain: [m.node_detail_state_draining, m.node_detail_draining_explanation],
		pause: [m.node_detail_state_paused, m.node_detail_paused_explanation]
	};
</script>

<Loaded resource={detail} back="/nodes">
	{#snippet children(d)}
		{@const n = d.summary}
		{@const name = n.hostname ?? n.address}
		<PageHeader title={name}>
			{#snippet meta()}{n.address}{/snippet}
			{#snippet actions()}
				{#if d.swarm !== null && may('/api/nodes/{id}/availability', 'POST')}
					{@const id = d.swarm.id}
					{#if d.swarm.availability === 'active'}
						<button type="button" class={button} onclick={() => panel.propose(proposal(m.infra_drain_title({ node: name }), 'post', '/api/nodes/{id}/availability', { path: { id }, body: { availability: 'drain' } }))}>{m.node_detail_drain()}</button>
					{:else}
						<button type="button" class={button} onclick={() => panel.propose(proposal(m.infra_return_title({ node: name }), 'post', '/api/nodes/{id}/availability', { path: { id }, body: { availability: 'active' } }))}>{m.node_detail_return_to_service()}</button>
					{/if}
				{/if}
			{/snippet}
		</PageHeader>
		<div class="grid gap-4 lg:grid-cols-3">
			<div class="flex flex-col gap-4 lg:col-span-2">
				{#if !n.reachable}
					<!-- 🔴 No gauge: an unreachable machine has no numbers, not zeros. -->
					<Card>
						<p class="text-sm text-critical">{n.problem === null ? n.detail : nodeProblem(n.problem)}</p>
						<p class="mt-2 {muted}">{m.node_detail_unreachable_no_measurement()}</p>
					</Card>
				{:else}
					<Card>
						{#if n.problem !== null}<p class="mb-3 text-sm text-critical">{nodeProblem(n.problem)}</p>{/if}
						<div class="grid gap-4 sm:grid-cols-3">
							{#if n.cpu_busy !== null}<Gauge label={m.node_detail_cpu()} value={n.cpu_busy} />{/if}
							{#if n.memory_used !== null}<Gauge label={m.node_detail_memory()} value={n.memory_used} />{/if}
							{#if n.swap_used !== null}<Gauge label={m.node_detail_swap()} value={n.swap_used} />{/if}
						</div>
						<h3 class="mt-5 mb-2 text-sm font-semibold">{m.node_detail_disks()}</h3>
						<div class="grid gap-3 sm:grid-cols-2">{#each n.disks as disk (disk.path)}<Disk {disk} />{/each}</div>
					</Card>
				{/if}
				<Card title={m.route_node_detail_tab_containers()}>
					{#if d.tasks.length === 0}<p class={muted}>{m.node_detail_no_containers()}</p>{/if}
					<ul class="space-y-1.5 text-sm">
						{#each d.tasks as t (t.id)}
							<li class={t.failed ? 'text-critical' : ''}>
								<a href="/apps/{t.service}" class="font-medium hover:underline">{t.service}</a> · {t.state}
								{#if t.explanation}<span class="block text-muted-text">{t.explanation}</span>{/if}
							</li>
						{/each}
					</ul>
				</Card>
			</div>
			<div class="flex flex-col gap-4">
				<Card title={m.node_detail_availability()}>
					{#if d.swarm === null}
						<p class={muted}>{m.node_detail_unknown_to_swarm()}</p>
					{:else}
						{@const state = availability[d.swarm.availability] ?? [m.node_detail_state_unknown, m.node_detail_unknown_explanation]}
						<p class="text-sm font-medium">{state[0]()}</p>
						<p class="mt-1 {muted}">{state[1]()}</p>
						{#if may('/api/nodes/{id}/availability', 'POST')}
							<!-- What the button in the header would do, said beside the state it changes. -->
							<p class="mt-3 text-sm">{d.swarm.availability === 'active' ? m.node_detail_drain_consequence() : m.node_detail_return_consequence()}</p>
						{/if}
					{/if}
				</Card>
				<Card>
					<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
						<dt class="text-muted-text">{m.node_detail_distro()}</dt><dd>{n.distro ?? m.nodes_unknown()}</dd>
						<dt class="text-muted-text">{m.node_detail_kernel()}</dt><dd>{n.kernel ?? m.nodes_unknown()}</dd>
						<dt class="text-muted-text">{m.node_detail_up_since()}</dt><dd>{n.uptime_s === null ? m.nodes_unknown() : duration(n.uptime_s)}</dd>
						<dt class="text-muted-text">{m.node_detail_last_report()}</dt><dd>{n.report_age_s === null ? m.nodes_unknown() : duration(n.report_age_s)}</dd>
					</dl>
				</Card>
				<Card title={m.route_node_detail_tab_network()}>
					{#if d.interfaces.length === 0}<p class={muted}>{m.node_detail_no_interfaces()}</p>{/if}
					<ul class="space-y-1 text-sm">
						{#each d.interfaces as i (i.name)}
							<li class="flex flex-wrap justify-between gap-2"><span class="font-mono text-xs">{i.name}</span><span class="text-muted-text">{m.node_detail_rx_tx({ rx: bytes(i.rx_bytes), tx: bytes(i.tx_bytes) })}</span></li>
						{/each}
					</ul>
				</Card>
			</div>
		</div>
	{/snippet}
</Loaded>

