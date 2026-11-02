<script lang="ts">
	import { limits } from '#lib/api/limits.ts';
	import { proposal, panel } from '#lib/action.svelte.ts';
	import type { Schemas } from '#lib/api/client.ts';
	import type { Column, Filter } from '#lib/listing.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Table from '#lib/ui/Table.svelte';
	import { input, primary } from '#lib/ui/styles.ts';
	import { day } from '#lib/format.ts';
	import { maintained, need, qualityOutcome, qualityRun } from '#lib/words.ts';

	type Item = Schemas['CatalogItem'];
	const catalog = read('/api/catalog');
	let installing = $state<string | null>(null);
	// The modal closes by clearing a boolean it is bound to; which application stays.
	let asking = $state(false);
	let domain = $state('');

	const columns: Column<Item>[] = [
		{ id: 'name', label: m.apps_column_name, value: (i) => i.display_name, cell: name },
		{ id: 'category', label: m.catalog_column_category, value: (i) => i.category, wide: true },
		// The manual steps are counted in the row and listed when installing: a sentence in
		// every row made the lines as tall as their longest prerequisite.
		{ id: 'before', label: m.catalog_column_before, value: (i) => i.prerequisites.length, numeric: true, wide: true, cell: before },
		// Sorted by what was proven: a failed step below an app never run, below one whole.
		{ id: 'proven', label: m.catalog_column_proven, value: provenRank, wide: true, cell: proven },
		{ id: 'state', label: m.catalog_column_state, value: (i) => (i.installed ? 1 : 0), cell: state }
	];

	function filtersFor(items: Item[]): Filter<Item>[] {
		const categories = [...new Set(items.map((i) => i.category).filter((c) => c !== null))].sort();
		return [
			{
				id: 'category',
				label: m.catalog_column_category,
				options: categories.map((c) => ({ value: c, label: () => c })),
				test: (i, v) => i.category === v
			}
		];
	}

	/** The first step of its last run that failed, if one did. */
	function failed(i: Item): string | undefined {
		const run = i.quality?.last;
		return run ? qualityRun(run).find(([, , o]) => o === 'failed')?.[1] : undefined;
	}

	function provenRank(i: Item): number | null {
		if (!i.quality) return null;
		if (!i.quality.last) return 1;
		return failed(i) === undefined ? 2 : 0;
	}

	function open(item: Item) {
		installing = item.name;
		domain = '';
		asking = true;
	}
</script>

{#snippet name(i: Item)}
	<span class="inline-flex items-center gap-2">
		{#if i.icon}
			<img src="/api/catalog/{i.name}/icon" alt="" class="size-5 shrink-0 rounded" loading="lazy" />
		{:else}
			<span aria-hidden="true" class="grid size-5 shrink-0 place-items-center rounded bg-raised-surface text-xs font-semibold text-muted-text">
				{i.display_name.charAt(0).toUpperCase()}
			</span>
		{/if}
		{i.display_name}
	</span>
{/snippet}

<!-- A zero is left blank: a column of zeros hides the one that is not. -->
{#snippet before(i: Item)}
	{#if i.prerequisites.length > 0}{m.catalog_manual_steps({ count: i.prerequisites.length })}{/if}
{/snippet}

<!-- Nothing at all for a source publishing no results: "not proven yet" would claim it
     was asked. -->
{#snippet proven(i: Item)}
	{#if i.quality}
		{@const step = failed(i)}
		<span class="text-sm whitespace-nowrap">
			{#if !i.quality.last}
				<span class="text-muted-text">{m.catalog_proven_none()}</span>
			{:else if step !== undefined}
				<span class="text-critical">{m.catalog_proven_failed({ step })}</span>
			{:else}
				{m.catalog_proven_whole()}
			{/if}
			<span class="text-muted-text">· {maintained(i.quality)}</span>
		</span>
	{/if}
{/snippet}

{#snippet state(i: Item)}
	{#if i.installed}
		<a href="/apps/{i.name}" class="text-sm whitespace-nowrap text-muted-text hover:text-accent hover:underline">{m.catalog_installed()}</a>
	{:else if may('/api/apps/{name}/install', 'POST')}
		<button type="button" class="text-sm whitespace-nowrap text-accent hover:underline" onclick={() => open(i)}>{m.catalog_install()}</button>
	{/if}
{/snippet}

<Loaded resource={catalog} empty={m.catalog_catalog_unreadable()}>
	{#snippet children(items)}
		{@const item = items.find((i) => i.name === installing)}
		<!-- What an application asks for and what must be done by hand are read once, at
		     the moment of installing it, over the list rather than in it. -->
		{#if item !== undefined}
			<Modal bind:open={asking} title={m.catalog_install_title({ app: item.display_name })}>
				{#if item.homepage}
					<a href={item.homepage} target="_blank" rel="noreferrer" class="self-start text-sm text-accent hover:underline">{m.catalog_homepage()}</a>
				{/if}
				<div class="min-w-0">
					<h3 class="mb-1 text-xs font-medium text-muted-text">{m.catalog_requires()}</h3>
					<ul class="list-disc space-y-0.5 pl-5 text-sm">
						{#each item.capabilities as c, i (i)}<li>{need(c)}</li>{/each}
					</ul>
				</div>
				{#if item.quality}
					<div class="min-w-0">
						<h3 class="mb-1 text-xs font-medium text-muted-text">
							{#if item.quality.last}
								{m.catalog_proven_title({ date: day(item.quality.last.date), version: item.quality.last.version, hlb: item.quality.last.hlb })}
							{:else}
								{m.catalog_proven_none()}
							{/if}
							· {maintained(item.quality)}
						</h3>
						{#if item.quality.last}
							<dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-sm">
								{#each qualityRun(item.quality.last) as [s, name, outcome] (s)}
									<dt>{name}</dt>
									<dd class={outcome === 'failed' ? 'text-critical' : outcome === 'not_run' ? 'text-muted-text' : ''}>{qualityOutcome(outcome)}</dd>
								{/each}
							</dl>
						{/if}
						<p class="mt-1 text-xs text-muted-text">{m.catalog_proven_explained()}</p>
					</div>
				{/if}
				{#if item.prerequisites.length > 0}
					<div class="min-w-0">
						<h3 class="mb-1 text-xs font-medium text-muted-text">{m.catalog_before_installing({ count: item.prerequisites.length })}</h3>
						<ol class="list-decimal space-y-0.5 pl-5 text-sm">
							{#each item.prerequisites as p (p)}<li>{p}</li>{/each}
						</ol>
					</div>
				{/if}
				<form
					class="flex flex-wrap items-end gap-2 border-t border-border pt-4"
					onsubmit={(e) => {
						e.preventDefault();
						asking = false;
						void panel.propose(
							proposal(m.catalog_install_title({ app: item.display_name }), 'post', '/api/apps/{name}/install', {
								path: { name: item.name },
								body: { domain: domain.trim() === '' ? null : domain.trim(), mail_domain: null }
							})
						);
					}}
				>
					{#if item.requests_domain}
						<label class="flex min-w-0 grow basis-48 flex-col gap-1 text-sm">
							{m.catalog_domain()}
							<input bind:value={domain} maxlength={limits.InstallRequest.domain.maxLength} placeholder={m.catalog_domain_hint()} autocapitalize="none" spellcheck="false" inputmode="url" class={input} />
						</label>
					{/if}
					<button type="submit" class={primary}>{m.app_detail_short_preview()}</button>
				</form>
			</Modal>
		{/if}
		<Table
			rows={items.toSorted((a, b) => a.display_name.localeCompare(b.display_name))}
			key={(i) => i.name}
			{columns}
			filters={filtersFor(items)}
			search={m.catalog_filter()}
			empty={m.catalog_catalog_unreadable()}
		/>
	{/snippet}
</Loaded>
