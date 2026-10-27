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
	import { need } from '#lib/words.ts';

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
