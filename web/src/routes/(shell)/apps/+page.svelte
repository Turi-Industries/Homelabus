<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import { duration } from '#lib/format.ts';
	import type { Column, Filter } from '#lib/listing.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Table from '#lib/ui/Table.svelte';
	import { tone } from '#lib/words.ts';

	type App = Schemas['AppSummary'];
	const apps = read('/api/apps');
	const rank = { critical: 0, notice: 1, ok: 2 };
	const attention = { ok: m.attention_ok, notice: m.attention_notice, critical: m.attention_critical };

	const columns: Column<App>[] = [
		{ id: 'name', label: m.apps_column_name, value: (a) => a.name, cell: name },
		{ id: 'address', label: m.apps_column_address, value: (a) => a.domain ?? a.image, wide: true },
		// The dot already says whether it runs; on a phone the column goes, the backup stays.
		{ id: 'status', label: m.app_detail_status, value: (a) => a.status, wide: true },
		// Never backed up sorts as the oldest: it is the worst a backup can be. An app
		// holding nothing owes no copy, so it sorts before the freshest.
		{ id: 'backup', label: m.app_detail_last_backup, value: (a) => (a.holds_data ? (a.last_backup_secs ?? Infinity) : -1), numeric: true, cell: backup },
		{
			id: 'verified',
			label: m.app_detail_last_verification,
			value: (a) => a.last_verification_secs ?? Infinity,
			numeric: true,
			wide: true,
			cell: verified
		},
		{ id: 'guides', label: m.apps_column_blocking, value: (a) => a.blocking_guides, numeric: true, wide: true, cell: guides }
	];
	const filters: Filter<App>[] = [
		{
			id: 'attention',
			label: m.apps_column_attention,
			options: (['critical', 'notice', 'ok'] as const).map((a) => ({ value: a, label: attention[a] })),
			test: (a, value) => a.attention === value
		}
	];
</script>

{#snippet name(a: App)}
	<span class="inline-flex items-center gap-2">
		<span aria-hidden="true" class={['size-2 shrink-0 rounded-full', tone[a.attention].bg]}></span>
		<!-- The catalogue's icon: a name is read, an icon is recognised. -->
		<img
			src="/api/catalog/{a.name}/icon"
			alt=""
			class="size-5 shrink-0 rounded"
			loading="lazy"
			onerror={(e) => ((e.currentTarget as HTMLImageElement).style.visibility = 'hidden')}
		/>
		{a.name}
		<span class="sr-only">— {attention[a.attention]()}</span>
	</span>
{/snippet}

{#snippet backup(a: App)}
	<span class={a.backup_attention === 'ok' ? undefined : tone[a.backup_attention].text}>
		{#if !a.holds_data}
			<span class="text-muted-text">{m.backups_nothing_to_back_up()}</span>
		{:else}
			{a.last_backup_secs === null ? m.backups_never() : duration(a.last_backup_secs)}
		{/if}
	</span>
{/snippet}

<!-- A zero is left blank: a column of zeros hides the one that is not. -->
{#snippet guides(a: App)}
	{#if a.blocking_guides > 0}<span class="text-critical">{a.blocking_guides}</span>{/if}
{/snippet}

{#snippet verified(a: App)}
	{a.last_verification_secs === null ? m.duration_never_verified() : duration(a.last_verification_secs)}
{/snippet}

<Loaded resource={apps}>
	{#snippet children(list)}
		<Table
			rows={list.toSorted((a, b) => rank[a.attention] - rank[b.attention] || a.name.localeCompare(b.name))}
			key={(a) => a.name}
			{columns}
			{filters}
			href={(a) => `/apps/${a.name}`}
			search={m.apps_filter()}
			empty={m.apps_no_application_installed()}
		/>
	{/snippet}
</Loaded>
