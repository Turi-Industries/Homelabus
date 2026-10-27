<script lang="ts" generics="T">
	import { TYPED } from '#lib/fields.ts';
	import { page } from '$app/state';
	import ArrowDown from '@lucide/svelte/icons/arrow-down';
	import ArrowUp from '@lucide/svelte/icons/arrow-up';
	import Search from '@lucide/svelte/icons/search';
	import { SvelteSet } from 'svelte/reactivity';
	import type { Snippet } from 'svelte';
	import { number } from '#lib/format.ts';
	import { parse, view, type Column, type Filter, type State } from '#lib/listing.ts';
	import { go as move } from '#lib/listing.svelte.ts';
	import { m } from '#lib/paraglide/messages.js';
	import Pager from './Pager.svelte';
	import { button, input } from './styles.ts';

	/**
	 * A list people compare and search: one line per row, the columns aligned so the eye
	 * runs down them, a search and filters held in the URL, and pages so that a thousand
	 * rows stay a page. A row with a destination leads there from its first cell — the
	 * one link in it, so a button in another cell is never also a click on the row.
	 */
	let {
		rows,
		key,
		columns,
		filters = [],
		href,
		search,
		empty,
		actions,
		paged,
		selection
	}: {
		rows: T[];
		key: (row: T) => string;
		columns: Column<T>[];
		filters?: Filter<T>[];
		/** Where a row leads; `undefined` for a row that leads nowhere. */
		href?: (row: T) => string | undefined;
		/** The search field's label: what is searched. */
		search: string;
		/** Said when there is nothing at all — not the same as nothing matching. */
		empty: string;
		actions?: Snippet;
		/**
		 * For a list the SERVER narrows and pages — one that only grows, like the audit
		 * log: `rows` is already the page, and this says what it is a page of. Sorting is
		 * the server's order then; the search and filters still live in the URL, where
		 * the page reads them to ask.
		 */
		paged?: { matched: number; total: number; size: number };
		/**
		 * What can be done to several rows at once. Given, each row gets a checkbox and
		 * this is drawn above the table, with the rows chosen — across pages.
		 */
		selection?: Snippet<[T[]]>;
	} = $props();

	const chosen = new SvelteSet<string>();
	const picked = $derived(rows.filter((r) => chosen.has(key(r))));

	const state = $derived(parse(page.url.searchParams, filters));
	const shown = $derived(
		paged === undefined
			? view(rows, columns, filters, state)
			: { shown: rows, matched: paged.matched, pages: Math.max(1, Math.ceil(paged.matched / paged.size)), page: state.page }
	);
	const total = $derived(paged?.total ?? rows.length);
	const narrowed = $derived(state.q.trim() !== '' || Object.values(state.filters).some((v) => v !== ''));

	const go = (next: Partial<State>) => move(state, next, filters);

	function sortBy(column: Column<T>) {
		const again = state.sort === column.id;
		go({ sort: again && state.desc ? null : column.id, desc: again && !state.desc });
	}

	/** `j` and `k` walk the rows, as in a mail client; Enter follows the row's link. */
	function walk(event: KeyboardEvent) {
		if (event.key !== 'j' && event.key !== 'k') return;
		if (event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement) return;
		const links = [...(event.currentTarget as HTMLElement).querySelectorAll<HTMLAnchorElement>('a[data-row]')];
		if (links.length === 0) return;
		const at = links.indexOf(document.activeElement as HTMLAnchorElement);
		const next = event.key === 'j' ? Math.min(at + 1, links.length - 1) : Math.max(at - 1, 0);
		links[at === -1 ? 0 : next]?.focus();
		event.preventDefault();
	}
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="flex flex-col gap-3" onkeydown={walk}>
	<div class="flex flex-wrap items-center gap-3">
		<label class="relative min-w-0 grow basis-48 sm:max-w-72">
			<span class="sr-only">{search}</span>
			<Search aria-hidden="true" class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-text" />
			<input
				type="search"
				value={state.q}
				maxlength={TYPED}
				oninput={(e) => go({ q: e.currentTarget.value })}
				placeholder={search}
				class={[input, 'w-full pl-8']}
			/>
		</label>
		{#each filters as f (f.id)}
			<label class="flex items-center gap-2 text-sm text-muted-text">
				{f.label()}
				<select
					value={state.filters[f.id] ?? ''}
					onchange={(e) => go({ filters: { ...state.filters, [f.id]: e.currentTarget.value } })}
					class={input}
				>
					<option value="">{m.table_all()}</option>
					{#each f.options as o (o.value)}<option value={o.value}>{o.label()}</option>{/each}
				</select>
			</label>
		{/each}
		<span class="text-sm text-muted-text tabular-nums" aria-live="polite">
			{narrowed
				? m.table_matched({ matched: number(shown.matched), total: number(total) })
				: m.table_total({ total: number(total) })}
		</span>
		{#if actions}<div class="ml-auto flex flex-wrap items-center gap-2">{@render actions()}</div>{/if}
	</div>

	{#if total === 0}
		<p class="py-6 text-sm text-muted-text">{empty}</p>
	{:else if shown.matched === 0}
		<div class="flex flex-wrap items-center gap-3 py-6">
			<p class="text-sm text-muted-text">{m.table_no_match()}</p>
			<button type="button" class={button} onclick={() => go({ q: '', filters: {} })}>{m.table_clear()}</button>
		</div>
	{:else}
		{#if selection && picked.length > 0}
			<div class="flex flex-wrap items-center gap-3 rounded-lg border border-accent px-3 py-2 text-sm">
				<span class="font-medium tabular-nums">{m.table_selected({ count: number(picked.length) })}</span>
				{@render selection(picked)}
				<button type="button" class={[button, 'ml-auto']} onclick={() => chosen.clear()}>{m.table_unselect()}</button>
			</div>
		{/if}
		<!-- The table scrolls inside its frame on a phone: the page itself never widens. -->
		<div class="overflow-x-auto rounded-lg border border-border bg-surface">
			<table class="w-full text-sm">
				<thead class="border-b border-border text-left text-xs text-muted-text">
					<tr>
						{#if selection}
							{@const all = shown.shown.length > 0 && shown.shown.every((r) => chosen.has(key(r)))}
							<th scope="col" class="w-10 px-3">
								<input
									type="checkbox"
									checked={all}
									aria-label={m.table_select_page()}
									onchange={() => shown.shown.forEach((r) => (all ? chosen.delete(key(r)) : chosen.add(key(r))))}
								/>
							</th>
						{/if}
						{#each columns as c (c.id)}
							<th
								scope="col"
								aria-sort={state.sort === c.id ? (state.desc ? 'descending' : 'ascending') : undefined}
								class={['h-(--row) px-3 font-medium whitespace-nowrap', c.numeric && 'text-right', c.wide && 'hidden md:table-cell']}
							>
								{#if c.value && paged === undefined}
									<button type="button" class="inline-flex items-center gap-1 rounded hover:text-text" onclick={() => sortBy(c)}>
										{c.label()}
										{#if state.sort === c.id}
											{@const Arrow = state.desc ? ArrowDown : ArrowUp}
											<Arrow aria-hidden="true" class="size-3" />
										{/if}
									</button>
								{:else}
									{c.label()}
								{/if}
							</th>
						{/each}
					</tr>
				</thead>
				<tbody>
					{#each shown.shown as row (key(row))}
						<tr class={['border-b border-border last:border-b-0 hover:bg-raised-surface', chosen.has(key(row)) && 'bg-raised-surface']}>
							{#if selection}
								<td class="w-10 px-3">
									<input
										type="checkbox"
										checked={chosen.has(key(row))}
										aria-label={m.table_select_row({ row: key(row) })}
										onchange={() => (chosen.has(key(row)) ? chosen.delete(key(row)) : chosen.add(key(row)))}
									/>
								</td>
							{/if}
							{#each columns as c, i (c.id)}
								<td class={['h-(--row) px-3 align-middle', c.numeric && 'text-right tabular-nums', c.wide && 'hidden md:table-cell']}>
									{#if i === 0 && href?.(row) !== undefined}
										<a data-row href={href?.(row)} class="font-medium hover:text-accent hover:underline">
											{@render content(row, c)}
										</a>
									{:else}
										{@render content(row, c)}
									{/if}
								</td>
							{/each}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>

		<Pager page={shown.page} pages={shown.pages} onpage={(page) => go({ page })} />
	{/if}
</div>

{#snippet content(row: T, c: Column<T>)}
	{#if c.cell}
		{@render c.cell(row)}
	{:else}
		{c.value?.(row) ?? '—'}
	{/if}
{/snippet}
