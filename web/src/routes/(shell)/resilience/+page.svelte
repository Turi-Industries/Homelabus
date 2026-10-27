<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import { muted } from '#lib/ui/styles.ts';
	import { tone, topology } from '#lib/words.ts';

	const resilience = read('/api/topology');
	const quorum = { holds: m.infra_quorum_holds, lost: m.infra_quorum_lost, unknown: m.infra_quorum_unknown };
</script>

<Loaded resource={resilience}>
	{#snippet children(t)}
		<div class="flex flex-col gap-4">
			<Card>
				<div class="flex flex-wrap items-start justify-between gap-2">
					<p class="min-w-0 grow basis-48 font-medium">{topology(t.verdict)}</p>
					<Mark attention={t.attention} />
				</div>
				<p class="mt-2 {muted}">{m.topology_anti_affinity_explanation()}</p>
			</Card>

			<Card title={m.topology_and_if_it_went_down()}>
				<p class="mb-3 {muted}">{m.topology_worst_case_at_top()}</p>
				<ul class="space-y-3">
					{#each t.simulations as s, i (i)}
						{@const target = 'domain' in s.target ? s.target.domain : s.target.node}
						<li class={['border-l-[3px] pl-3', tone[s.attention].border]}>
							<div class="flex flex-wrap items-baseline justify-between gap-2">
								<p class="font-medium">{m.infra_if_lost({ target })}</p>
								<p class="text-xs text-muted-text">
									{m.infra_remaining({ count: s.remaining_nodes })} ·
									<span class={s.quorum === 'lost' ? 'font-semibold text-critical' : ''}>{quorum[s.quorum]()}</span>
								</p>
							</div>
							<p class="text-sm">{s.services_lost.length > 0 ? m.infra_goes_down({ list: s.services_lost.join(', ') }) : m.infra_nothing_goes_down()}</p>
							{#if s.services_reduced.length > 0}
								<p class="text-sm text-muted-text">{m.infra_reduced({ list: s.services_reduced.map((r) => `${r.service} ${r.before}→${r.after}`).join(', ') })}</p>
							{/if}
							{#if s.unknown_domain}<p class="text-sm text-attention">{m.topology_undeclared_domain_explanation()}</p>{/if}
						</li>
					{/each}
				</ul>
			</Card>

			{#if t.violations.length > 0}
				<Card title={m.topology_overstated_redundancy()}>
					<ul class="space-y-1.5 text-sm">
						{#each t.violations as v, i (i)}
							<li class={v.total_violation ? 'text-critical' : ''}>{v.explanation}</li>
						{/each}
					</ul>
				</Card>
			{/if}

			<Card title={m.topology_outage_domains()}>
				<div class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
					{#each t.domains as d, i (i)}
						<div class={['rounded-lg border p-3', d.concentrated ? 'border-attention' : 'border-border']}>
							<p class="font-medium">{d.name ?? m.topology_undeclared_domain()}</p>
							{#if d.concentrated}<p class="text-xs text-attention">{m.topology_concentrated_domain_explanation()}</p>{/if}
							{#if d.name === null}<p class="text-xs text-attention">{m.topology_undeclared_domain_explanation()}</p>{/if}
							<ul class="mt-2 space-y-1 text-sm">
								{#each d.nodes as n (n.id)}
									<li>
										<span class={n.reachable ? '' : 'text-critical'}>{n.hostname}</span>
										<span class="text-xs text-muted-text">{n.tier === null ? '' : `${m.infra_tier({ tier: n.tier })} · `}{n.services.length > 0 ? n.services.join(', ') : m.topology_no_service()}</span>
									</li>
								{/each}
							</ul>
						</div>
					{/each}
				</div>
			</Card>
		</div>
	{/snippet}
</Loaded>
