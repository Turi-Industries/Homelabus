<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import { reason } from '#lib/causes.ts';
	import type { Column, Filter } from '#lib/listing.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Table from '#lib/ui/Table.svelte';
	import { code, muted } from '#lib/ui/styles.ts';
	import { reach, tone } from '#lib/words.ts';

	type Route = Schemas['ExposureSummary'];
	const exposure = read('/api/exposure');
	const rank = { critical: 0, notice: 1, ok: 2 };
	const attention = { ok: m.attention_ok, notice: m.attention_notice, critical: m.attention_critical };

	const columns: Column<Route>[] = [
		{ id: 'host', label: m.exposure_column_host, value: (r) => r.host, cell: host },
		{ id: 'app', label: m.exposure_column_app, value: (r) => r.app },
		{ id: 'declared', label: m.exposure_column_declared, value: (r) => r.declared, wide: true },
		{ id: 'reach', label: m.exposure_column_reach, value: (r) => reach[r.reach]() },
		{ id: 'divergence', label: m.exposure_column_divergence, value: (r) => (r.cause === null ? null : reason(r.cause.kind)), cell: divergence }
	];
	const filters: Filter<Route>[] = [
		{
			id: 'attention',
			label: m.apps_column_attention,
			options: (['critical', 'notice', 'ok'] as const).map((a) => ({ value: a, label: attention[a] })),
			test: (r, v) => r.attention === v
		}
	];
</script>

{#snippet host(r: Route)}
	<span class="inline-flex items-center gap-2 font-mono">
		<span aria-hidden="true" class={['size-2 shrink-0 rounded-full', tone[r.attention].bg]}></span>
		{r.host}
		<span class="sr-only">— {attention[r.attention]()}</span>
	</span>
{/snippet}
<!-- The gap as the controller decided it, worded here; its sentence is the CLI's. -->
{#snippet divergence(r: Route)}{#if r.cause !== null}<span class="text-critical">{reason(r.cause.kind) ?? r.divergence}</span>{/if}{/snippet}

<p class="mb-3 {muted}">{m.security_exposure_explanation()}</p>
<Loaded resource={exposure}>
	{#snippet children(rows)}
		{@const diverged = rows.filter((r) => r.divergence !== null).length}
		{#if diverged > 0}
			<p class="mb-3 text-sm">
				<span class="font-medium text-critical">{m.security_divergence_count({ count: diverged })}</span>
				<span class="text-muted-text">{m.security_divergence_explanation()}</span>
			</p>
		{/if}
		<Table
			rows={rows.toSorted((a, b) => rank[a.attention] - rank[b.attention])}
			key={(r) => r.host}
			{columns}
			{filters}
			href={(r) => (r.installed ? `/apps/${r.app}` : undefined)}
			search={m.exposure_search()}
			empty={m.security_no_route_exposed()}
		/>
		<code class="mt-3 block {code}">{m.security_ingress_command()}</code>
	{/snippet}
</Loaded>
