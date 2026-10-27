<script lang="ts">
	import { page } from '$app/state';
	import type { Schemas } from '#lib/api/client.ts';
	import { when } from '#lib/format.ts';
	import { parse, type Column, type Filter } from '#lib/listing.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Table from '#lib/ui/Table.svelte';
	import { button, muted } from '#lib/ui/styles.ts';

	type Entry = Schemas['AuditItem'];
	const verdict: Record<string, [() => string, string]> = {
		ok: [m.journal_verdict_ok, 'text-muted-text'],
		failed: [m.journal_verdict_failed, 'text-critical'],
		refused: [m.journal_verdict_refused, 'text-attention']
	};

	// The server narrows the log — it only grows — so the filter's test is never run here.
	const filters: Filter<Entry>[] = [
		{
			id: 'outcome',
			label: m.audit_column_outcome,
			options: Object.entries(verdict).map(([value, [label]]) => ({ value, label })),
			test: () => true
		}
	];
	const wanted = $derived(parse(page.url.searchParams, filters));
	const audit = $derived(
		read('/api/audit', {
			query: { q: wanted.q.trim() || undefined, outcome: wanted.filters.outcome || undefined, page: wanted.page }
		})
	);

	// Each search is another request: the page it answers replaces the one on screen
	// when it arrives, never before — or the field being typed in would vanish with it.
	let held = $state.raw<Schemas['AuditPage'] | undefined>();
	$effect(() => {
		if (audit.data !== undefined) held = audit.data;
	});
	// `Loaded` watches only until the first page; the table keeps it fresh after.
	$effect(() => audit.watch());

	const columns: Column<Entry>[] = [
		{ id: 'at', label: m.audit_column_at, cell: at },
		{ id: 'who', label: m.audit_column_who, cell: who },
		{ id: 'what', label: m.audit_column_what, cell: what },
		{ id: 'outcome', label: m.audit_column_outcome, cell: outcome },
		{ id: 'detail', label: m.audit_column_detail, wide: true, cell: detail }
	];
</script>

{#snippet at(e: Entry)}<span class="whitespace-nowrap text-muted-text tabular-nums">{when(e.at)}</span>{/snippet}
{#snippet who(e: Entry)}{m.journal_actor_with_role({ actor: e.actor, role: e.role })}{/snippet}
{#snippet what(e: Entry)}{m.journal_action_on_target({ action: e.action, target: e.target })}{/snippet}
{#snippet outcome(e: Entry)}
	{@const v = verdict[e.outcome] ?? [() => e.outcome, 'text-muted-text']}
	<span class={v[1]}>{v[0]()}</span>
{/snippet}
{#snippet detail(e: Entry)}<span class="text-muted-text">{e.detail ?? ''}</span>{/snippet}

{#snippet table(p: Schemas['AuditPage'])}
	<Table
		rows={p.entries}
		key={(e) => String(e.id)}
		{columns}
		{filters}
		search={m.audit_filter()}
		empty={m.journal_no_action_recorded()}
		paged={{ matched: p.matched, total: p.total, size: p.page_size }}
	>
		{#snippet actions()}<a href="/api/export/audit" download class={button}>{m.export_csv()}</a>{/snippet}
	</Table>
{/snippet}

<p class="mb-3 {muted}">{m.journal_integrity_explanation()}</p>

{#if held === undefined}
	<Loaded resource={audit}>
		{#snippet children(p)}{@render table(p)}{/snippet}
	</Loaded>
{:else}
	{#if audit.error !== undefined}<p role="alert" class="mb-3 text-sm text-critical">{m.state_never_received({ error: audit.error })}</p>{/if}
	{@render table(held)}
{/if}
