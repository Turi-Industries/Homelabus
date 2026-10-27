<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import { when } from '#lib/format.ts';
	import type { Column, Filter } from '#lib/listing.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Table from '#lib/ui/Table.svelte';
	import { button, muted } from '#lib/ui/styles.ts';

	type Run = Schemas['BackupRun'];
	const runs = read('/api/backups');
	const results = { ok: m.runs_result_ok, failed: m.runs_result_failed };

	const columns: Column<Run>[] = [
		{ id: 'app', label: m.runs_column_app, value: (r) => r.app },
		{ id: 'when', label: m.runs_column_when, value: (r) => r.when, cell: at },
		{ id: 'kind', label: m.runs_column_kind, value: (r) => r.kind, wide: true },
		{ id: 'destination', label: m.runs_column_destination, value: (r) => r.destination },
		{ id: 'result', label: m.runs_column_result, value: (r) => r.error ?? results[r.succeeded ? 'ok' : 'failed'](), cell: result }
	];
	const filters: Filter<Run>[] = [
		{
			id: 'result',
			label: m.runs_column_result,
			options: (['failed', 'ok'] as const).map((v) => ({ value: v, label: results[v] })),
			test: (r, v) => r.succeeded === (v === 'ok')
		}
	];
</script>

{#snippet at(r: Run)}<span class="whitespace-nowrap tabular-nums">{when(r.when)}</span>{/snippet}
{#snippet result(r: Run)}
	{#if r.succeeded}<span class="text-muted-text">{results.ok()}</span>{:else}<span class="text-critical">{r.error ?? results.failed()}</span>{/if}
{/snippet}

<Loaded resource={runs}>
	{#snippet children(list)}
		<p class="mb-3 {muted}">{m.runs_window({ count: list.length })}</p>
		<Table
			rows={list}
			key={(r) => String(r.id)}
			{columns}
			{filters}
			href={(r) => `/apps/${r.app}/backups`}
			search={m.runs_search()}
			empty={m.backups_no_run_recorded()}
		>
			{#snippet actions()}<a href="/api/export/backups" download class={button}>{m.export_csv()}</a>{/snippet}
		</Table>
	{/snippet}
</Loaded>
