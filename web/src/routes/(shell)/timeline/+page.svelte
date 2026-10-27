<script lang="ts">
	import { TYPED } from '#lib/fields.ts';
	import { daysAgo } from '#lib/format.ts';
	import { page } from '$app/state';
	import { go } from '#lib/listing.svelte.ts';
	import { parse, view, type Column, type Filter } from '#lib/listing.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { getLocale } from '#lib/paraglide/runtime.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Pager from '#lib/ui/Pager.svelte';
	import { input, muted } from '#lib/ui/styles.ts';
	import type { Schemas } from '#lib/api/client.ts';
	import { tone } from '#lib/words.ts';

	type Kind = Schemas['EventKind'];
	type Event = Schemas['Event'];
	const timeline = read('/api/timeline');
	const kinds: Record<Kind, () => string> = {
		backup: m.timeline_kind_backup,
		verification: m.timeline_kind_verification,
		action: m.timeline_kind_action,
		alert: m.timeline_kind_alert
	};

	function day(seconds: number): string {
		const date = new Date(seconds * 1000);
		const days = daysAgo(seconds);
		if (days <= 0) return m.timeline_today();
		if (days === 1) return m.timeline_yesterday();
		return `${new Intl.DateTimeFormat(getLocale(), { dateStyle: 'full' }).format(date)} — ${m.timeline_days_ago({ days })}`;
	}
	// A river, not a table: it keeps its days. The search, the kind and the page are
	// held in the URL all the same, so a filtered river survives a reload.
	const searched: Column<Event>[] = [
		{ id: 'target', label: m.timeline_title, value: (e) => e.target },
		{ id: 'what', label: m.timeline_title, value: (e) => e.what }
	];
	const filters: Filter<Event>[] = [
		{
			id: 'kind',
			label: m.timeline_filter_all,
			options: (Object.keys(kinds) as Kind[]).map((k) => ({ value: k, label: kinds[k] })),
			test: (e, v) => e.kind_of === v
		}
	];
	const wanted = $derived(parse(page.url.searchParams, filters));
	const kind = $derived((wanted.filters.kind ?? null) as Kind | null);

	const time = (seconds: number) =>
		new Intl.DateTimeFormat(getLocale(), { timeStyle: 'short' }).format(new Date(seconds * 1000));
</script>

<Card title={m.timeline_title()}>
	<p class="mb-3 {muted}">{m.timeline_river_explanation()}</p>
	<div class="mb-4 flex flex-wrap items-center gap-2">
		{#each [null, ...(Object.keys(kinds) as Kind[])] as k (k)}
			<button
				type="button"
				aria-pressed={kind === k}
				class={['rounded-full border px-3 py-1 text-sm', kind === k ? 'border-accent text-accent' : 'border-border text-muted-text hover:text-text']}
				onclick={() => go(wanted, { filters: { kind: k ?? '' } }, filters)}>{k === null ? m.timeline_filter_all() : kinds[k]()}</button
			>
		{/each}
		<input
			type="search"
			value={wanted.q}
			maxlength={TYPED}
			oninput={(e) => go(wanted, { q: e.currentTarget.value }, filters)}
			placeholder={m.timeline_search()}
			aria-label={m.timeline_search()}
			class={[input, 'min-w-0 grow basis-48 sm:max-w-64']}
		/>
	</div>
	<Loaded resource={timeline} empty={m.timeline_nothing_recorded_yet()}>
		{#snippet children(events)}
			{@const v = view(events, searched, filters, wanted)}
			{@const shown = v.shown}
			<p class="mb-3 text-xs {muted}">{m.timeline_window({ count: events.length })}</p>
			{#each shown as e, i (i)}
				{#if i === 0 || day(shown[i - 1]?.when ?? 0) !== day(e.when)}
					<h3 class="mt-4 mb-2 text-xs font-semibold tracking-wide text-muted-text uppercase first:mt-0">{day(e.when)}</h3>
				{/if}
				<div class="flex gap-3 py-1 text-sm">
					<span class="w-16 shrink-0 text-xs whitespace-nowrap text-muted-text tabular-nums">{time(e.when)}</span>
					<span aria-hidden="true" class={['mt-1.5 size-2 shrink-0 rounded-full', tone[e.attention].bg]}></span>
					<span class="min-w-0 flex-1"><span class="font-medium">{e.target}</span> — {e.what}</span>
				</div>
			{:else}
				<p class="py-4 text-sm text-muted-text">{m.table_no_match()}</p>
			{/each}
			<div class="mt-4"><Pager page={v.page} pages={v.pages} onpage={(p) => go(wanted, { page: p }, filters)} /></div>
		{/snippet}
	</Loaded>
</Card>
