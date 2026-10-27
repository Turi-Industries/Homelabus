<script lang="ts">
	import { goto } from '$app/navigation';
	import ArrowDown from '@lucide/svelte/icons/arrow-down';
	import ArrowUp from '@lucide/svelte/icons/arrow-up';
	import LayoutGrid from '@lucide/svelte/icons/layout-grid';
	import Plus from '@lucide/svelte/icons/plus';
	import X from '@lucide/svelte/icons/x';
	import { api } from '#lib/api/client.ts';
	import { limits } from '#lib/api/limits.ts';
	import { allowed } from '#lib/api/rights.ts';
	import Dashboard from '#lib/home/Dashboard.svelte';
	import { shownWindow, WINDOWS, type Window } from '#lib/home/history.svelte.ts';
	import { pack } from '#lib/home/layout.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read, refusal } from '#lib/resource.svelte.ts';
	import { me } from '#lib/session.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import { input } from '#lib/ui/styles.ts';
	import { widgets, type HomeTile } from '#lib/widgets.ts';

	const person = $derived(me().data);
	const can = $derived(person?.can);
	const preferences = read('/api/preferences');
	$effect(() => preferences.watch());

	// The home is the console's: a person who may read nothing of it has theirs in "Me".
	$effect(() => {
		if (can !== undefined && !can.read) void goto('/me', { replaceState: true });
	});

	const windowWords: Record<Window, () => string> = { hour: m.window_hour, six_hours: m.window_six_hours, day: m.window_day };

	let arranging = $state(false);
	let saveError = $state<string | undefined>();
	// What the person just arranged, shown before the server confirms it.
	let local = $state.raw<HomeTile[] | undefined>();

	const offered = $derived((preferences.data?.home_offered ?? []).filter((t) => allowed(can, widgets[t.widget].reads, 'GET')));
	const shown = $derived(
		(local ?? preferences.data?.home ?? preferences.data?.home_default ?? []).filter((t) =>
			offered.some((o) => o.widget === t.widget)
		)
	);
	const unpinned = $derived(offered.filter((o) => !shown.some((t) => t.widget === o.widget)));
	// The sizes a tile can take, from the bounds the controller refuses past.
	const widths = $derived(range(limits.HomeTile.w.minimum, limits.HomeTile.w.maximum));
	const heights = $derived(range(limits.HomeTile.h.minimum, limits.HomeTile.h.maximum));
	const preview = $derived(pack(shown, limits.HomeTile.w.maximum));

	function range(from: number, to: number): number[] {
		return Array.from({ length: to - from + 1 }, (_, i) => from + i);
	}

	async function arrange(home: HomeTile[] | null) {
		local = home ?? undefined;
		const { error, response } = await api.PUT('/api/preferences/home', { body: { home } });
		saveError = response.ok ? undefined : refusal(error, response);
		await preferences.refresh();
		local = undefined;
	}

	function move(i: number, by: number) {
		const next = [...shown];
		const [tile] = next.splice(i, 1);
		if (tile === undefined) return;
		next.splice(i + by, 0, tile);
		void arrange(next);
	}

	function resize(i: number, size: Partial<Pick<HomeTile, 'w' | 'h'>>) {
		void arrange(shown.map((t, j) => (j === i ? { ...t, ...size } : t)));
	}
</script>

{#if person !== undefined && can?.read}
	<!-- One row above the tiles: the period every curve shows, then the arrangement. -->
	<div class="mb-3 flex flex-wrap items-center justify-between gap-2">
		<nav aria-label={m.window_label()} class="flex rounded-md border border-border p-0.5 text-sm">
			{#each WINDOWS as w (w)}
				<a
					href="?window={w}"
					data-sveltekit-replacestate
					data-sveltekit-noscroll
					aria-current={shownWindow() === w ? 'true' : undefined}
					class={['rounded px-2 py-0.5 tabular-nums', shownWindow() === w ? 'bg-raised-surface font-medium text-text' : 'text-muted-text hover:text-text']}
					>{windowWords[w]()}</a
				>
			{/each}
		</nav>
		{#if person.account !== null && can.act_on_self}
			<button type="button" class="flex items-center gap-1.5 rounded-md px-2 py-1 text-sm text-muted-text hover:bg-raised-surface hover:text-text" onclick={() => (arranging = true)}>
				<LayoutGrid aria-hidden="true" class="size-4" />{m.home_arrange()}
			</button>
		{/if}
	</div>
	{#if saveError !== undefined}
		<p role="alert" class="mb-3 text-sm text-critical">{m.home_save_failed({ error: saveError })}</p>
	{/if}
	<Loaded resource={preferences}>
		{#snippet children()}
			<Dashboard tiles={shown} />
		{/snippet}
	</Loaded>
{/if}

<Modal bind:open={arranging} title={m.home_arrange_title()}>
	<!-- The layout as it will land, drawn from the same packing as the home itself. -->
	{#if shown.length > 0}
		<figure class="flex flex-col gap-1">
			<div
				class="grid gap-1"
				style:grid-template-columns="repeat({limits.HomeTile.w.maximum}, minmax(0, 1fr))"
				style:grid-template-rows="repeat({preview.rows}, 2rem)"
			>
				{#each shown as tile, i (tile.widget)}
					{@const p = preview.placed[i]}
					{#if p !== undefined}
						<span
							class="flex min-w-0 items-center justify-center truncate rounded border border-border bg-raised-surface px-1 text-xs"
							style:grid-column="{p.x + 1} / span {p.w}"
							style:grid-row="{p.y + 1} / span {p.h}">{widgets[tile.widget].label()}</span
						>
					{/if}
				{/each}
			</div>
			<figcaption class="text-xs text-muted-text">{m.home_layout_preview()}</figcaption>
		</figure>

		<p class="text-sm font-medium">{m.home_tiles()}</p>
		<ol class="space-y-1">
			{#each shown as tile, i (tile.widget)}
				{@const label = widgets[tile.widget].label()}
				<li class="flex flex-wrap items-center gap-2">
					<span class="min-w-0 grow basis-32 text-sm">{label}</span>
					<select value={tile.w} aria-label="{label} — {m.home_tile_width()}" title={m.home_tile_width()} class={[input, 'py-0.5']} onchange={(e) => resize(i, { w: Number(e.currentTarget.value) })}>
						{#each widths as w (w)}<option value={w}>{w} ↔</option>{/each}
					</select>
					<select value={tile.h} aria-label="{label} — {m.home_tile_height()}" title={m.home_tile_height()} class={[input, 'py-0.5']} onchange={(e) => resize(i, { h: Number(e.currentTarget.value) })}>
						{#each heights as h (h)}<option value={h}>{h} ↕</option>{/each}
					</select>
					<button type="button" disabled={i === 0} aria-label="{label} — {m.home_move_up()}" class="rounded p-1 hover:bg-raised-surface disabled:opacity-30" onclick={() => move(i, -1)}><ArrowUp class="size-4" /></button>
					<button type="button" disabled={i === shown.length - 1} aria-label="{label} — {m.home_move_down()}" class="rounded p-1 hover:bg-raised-surface disabled:opacity-30" onclick={() => move(i, 1)}><ArrowDown class="size-4" /></button>
					<button type="button" aria-label="{label} — {m.home_unpin()}" class="rounded p-1 hover:bg-raised-surface" onclick={() => arrange(shown.filter((t) => t.widget !== tile.widget))}><X class="size-4" /></button>
				</li>
			{/each}
		</ol>
	{/if}

	<p class="text-sm font-medium">{m.home_add()}</p>
	{#if unpinned.length === 0}
		<p class="text-sm text-muted-text">{m.home_all_pinned()}</p>
	{/if}
	<div class="flex flex-wrap gap-2">
		{#each unpinned as tile (tile.widget)}
			<button type="button" class="flex items-center gap-1 rounded-full border border-border px-3 py-1 text-sm hover:bg-raised-surface" onclick={() => arrange([...shown, tile])}>
				<Plus class="size-3.5" />{widgets[tile.widget].label()}
			</button>
		{/each}
	</div>
	{#if preferences.data?.home !== null}
		<button type="button" class="self-start text-sm text-accent hover:underline" onclick={() => arrange(null)}>{m.home_reset()}</button>
	{/if}
	{#if saveError !== undefined}
		<p role="alert" class="text-sm text-critical">{m.home_save_failed({ error: saveError })}</p>
	{/if}
</Modal>
