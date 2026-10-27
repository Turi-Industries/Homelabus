<script lang="ts">
	import { TYPED } from '#lib/fields.ts';
	import { goto } from '$app/navigation';
	import type { Rights } from '#lib/api/rights.ts';
	import { allowed } from '#lib/api/rights.ts';
	import { modules } from '#lib/modules/index.ts';
	import { pagesFor, source, type Entry } from '#lib/modules/module.ts';
	import { m } from '#lib/paraglide/messages.js';

	/**
	 * `Ctrl+K`: every page this person is offered, and whatever the modules let one find
	 * by name — an application, a machine. Built from the modules, like the navigation,
	 * so a page written is a page found.
	 */
	let { can, open = $bindable(false) }: { can: Rights; open?: boolean } = $props();

	let dialog = $state<HTMLDialogElement>();
	let query = $state('');
	let selected = $state(0);

	const searches = $derived(
		modules.flatMap((module) =>
			module.search !== undefined && allowed(can, module.search.path, 'GET')
				? [{ module, search: module.search, resource: source(module.search.path) }]
				: []
		)
	);

	$effect(() => {
		if (!open) return;
		const stops = searches.map((s) => s.resource.watch());
		return () => stops.forEach((stop) => stop());
	});

	const entries = $derived.by((): Entry[] => {
		const pages = modules.flatMap((module) =>
			pagesFor(module, can).map((page) => ({
				label: page.label(),
				hint: module.label(),
				href: page.path
			}))
		);
		const found = searches.flatMap((s) =>
			s.resource.data === undefined ? [] : s.search.entries(s.resource.data)
		);
		return [...pages, ...found];
	});

	const matches = $derived.by(() => {
		const words = query.toLowerCase().split(/\s+/).filter(Boolean);
		return entries
			.filter((e) => words.every((w) => `${e.label} ${e.hint}`.toLowerCase().includes(w)))
			.slice(0, 50);
	});

	$effect(() => {
		if (open && dialog && !dialog.open) {
			query = '';
			selected = 0;
			dialog.showModal();
		} else if (!open && dialog?.open) {
			dialog.close();
		}
	});

	function go(entry: Entry | undefined) {
		if (entry === undefined) return;
		open = false;
		void goto(entry.href);
	}

	function keys(e: KeyboardEvent) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			selected = Math.min(selected + 1, matches.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			selected = Math.max(selected - 1, 0);
		} else if (e.key === 'Enter') {
			e.preventDefault();
			go(matches[selected]);
		}
	}
</script>

<dialog
	bind:this={dialog}
	aria-label={m.palette_label()}
	onclose={() => (open = false)}
	class="mx-auto mt-[12vh] w-[min(36rem,calc(100vw-2rem))] rounded-xl border border-border bg-surface p-0 text-text backdrop:bg-background/70"
>
	<input
		bind:value={query}
		maxlength={TYPED}
		oninput={() => (selected = 0)}
		onkeydown={keys}
		placeholder={m.palette_placeholder()}
		aria-label={m.palette_label()}
		role="combobox"
		aria-expanded="true"
		aria-controls="palette-results"
		aria-activedescendant={matches[selected] ? `palette-${selected}` : undefined}
		class="w-full border-b border-border bg-transparent px-4 py-3 outline-none"
	/>
	<ul id="palette-results" role="listbox" class="max-h-[50vh] overflow-y-auto p-2">
		{#each matches as entry, i (entry.href)}
			<li
				id="palette-{i}"
				role="option"
				aria-selected={i === selected}
				class={[
					'flex cursor-pointer flex-wrap items-baseline justify-between gap-x-4 rounded-md px-3 py-2',
					i === selected && 'bg-raised-surface'
				]}
				onclick={() => go(entry)}
				onkeydown={() => undefined}
				onmousemove={() => (selected = i)}
			>
				<span class="min-w-0">{entry.label}</span>
				<span class="text-xs text-muted-text">{entry.hint}</span>
			</li>
		{:else}
			<li class="px-3 py-2 text-sm text-muted-text">{m.palette_nothing()}</li>
		{/each}
	</ul>
</dialog>
