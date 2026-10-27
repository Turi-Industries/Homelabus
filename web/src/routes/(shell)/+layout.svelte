<script lang="ts">
	import type { Snippet } from 'svelte';
	import { page } from '$app/state';
	import House from '@lucide/svelte/icons/house';
	import LogOut from '@lucide/svelte/icons/log-out';
	import Menu from '@lucide/svelte/icons/menu';
	import Search from '@lucide/svelte/icons/search';
	import X from '@lucide/svelte/icons/x';
	import { api } from '#lib/api/client.ts';
	import { allowed } from '#lib/api/rights.ts';
	import { concerning, lines } from '#lib/inbox.svelte.ts';
	import { modules, moduleOf } from '#lib/modules/index.ts';
	import { pagesFor } from '#lib/modules/module.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read, refreshAll } from '#lib/resource.svelte.ts';
	import { me } from '#lib/session.ts';
	import ActionPanel from '#lib/ui/ActionPanel.svelte';
	import CommandPalette from '#lib/ui/CommandPalette.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Source from '#lib/ui/Source.svelte';

	let { children }: { children: Snippet } = $props();

	const who = me();
	const brand = read('/api/appearance');
	$effect(() => brand.watch());

	// One read for the whole inbox: the controller gathers every source this person may
	// read and groups it by cause. It stays fresh while the shell is up — the
	// navigation's counts are made of it.
	const issues = read('/api/issues');
	const reads = $derived(allowed(who.data?.can, '/api/issues', 'GET'));
	$effect(() => {
		if (reads) return issues.watch();
	});

	// Named from the modules, like the navigation: a tab, a screen reader and the
	// history all say where this is. A detail page is named by what it is about.
	const title = $derived.by(() => {
		const house = brand.data?.name ?? 'Homelabus';
		const path = page.url.pathname;
		const module = moduleOf(path);
		if (module === undefined) return house;
		const here = module.pages.find((p) => p.path === path);
		const about = here?.label() ?? decodeURIComponent(path.split('/')[2] ?? '');
		return [about, module.label(), house].filter((part, i, all) => part !== '' && all.indexOf(part) === i).join(' · ');
	});

	let menuOpen = $state(false);
	let paletteOpen = $state(false);
	let helpOpen = $state(false);

	function signIn(): string {
		return `/auth/signin?return_to=${encodeURIComponent(page.url.pathname + page.url.search)}`;
	}

	async function signOut() {
		await api.POST('/auth/signout');
		location.assign('/');
	}

	function keys(e: KeyboardEvent) {
		const typing = e.target instanceof HTMLElement && e.target.closest('input, textarea, select');
		if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
			e.preventDefault();
			paletteOpen = true;
		} else if (!typing && e.key === '/') {
			e.preventDefault();
			paletteOpen = true;
		} else if (!typing && e.key === '?') {
			helpOpen = !helpOpen;
		} else if (e.key === 'Escape' && helpOpen) {
			// Not a native `<dialog>`, which closes on Escape by itself: the overlay
			// lists Esc as what closes a panel, so it has to close on it too.
			helpOpen = false;
		}
	}
</script>

<svelte:head><title>{title}</title></svelte:head>
<svelte:window onkeydown={keys} />
<svelte:document onvisibilitychange={() => document.visibilityState === 'visible' && void refreshAll()} />

{#if who.status === 401}
	<main class="mx-auto flex min-h-dvh max-w-sm flex-col justify-center gap-4 p-6">
		<p class="text-lg font-semibold">{brand.data?.name ?? 'Homelabus'}</p>
		<p class="text-muted-text">{m.state_signed_out()}</p>
		<a href={signIn()} class="self-start rounded-md bg-accent px-4 py-2 font-semibold text-on-accent">
			{m.state_sign_in()}
		</a>
		<Source />
	</main>
{:else}
	<Loaded resource={who}>
		{#snippet children(person)}
			{@render shell(person)}
		{/snippet}
	</Loaded>
{/if}

{#snippet shell(person: NonNullable<typeof who.data>)}
	{@const can = person.can}
	{@const items = reads ? lines(issues.data ?? []) : []}
	{@const current = moduleOf(page.url.pathname)}
	{@const tabs = current === undefined ? [] : pagesFor(current, can)}
	{@const unreachable = who.error !== undefined || (reads && issues.error !== undefined)}

	<div class="flex min-h-dvh">
		<nav
			aria-label={m.nav_main()}
			class={[
				'fixed inset-y-0 left-0 z-30 flex w-64 flex-col border-r border-border bg-surface transition-transform md:sticky md:top-0 md:h-dvh md:translate-x-0',
				menuOpen ? 'translate-x-0' : 'invisible -translate-x-full md:visible'
			]}
		>
			<div class="flex items-center justify-between gap-2 px-4 py-4">
				<a href="/" class="flex min-w-0 items-center gap-2 font-semibold" onclick={() => (menuOpen = false)}>
					{#if brand.data?.logo}
						<img src="/api/appearance/logo" alt="" class="size-7 rounded" />
					{/if}
					<span class="truncate">{brand.data?.name ?? 'Homelabus'}</span>
				</a>
				<button type="button" class="md:hidden" aria-label={m.nav_close_menu()} onclick={() => (menuOpen = false)}>
					<X class="size-5" />
				</button>
			</div>

			<button
				type="button"
				class="mx-3 mb-3 flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm text-muted-text hover:bg-raised-surface"
				onclick={() => (paletteOpen = true)}
			>
				<Search class="size-4" />
				<span class="flex-1 text-left">{m.palette_open()}</span>
				<kbd class="text-xs">{m.palette_shortcut_hint()}</kbd>
			</button>

			<ul class="flex-1 space-y-0.5 overflow-y-auto px-3">
				{#if can.read}
					{@const inView = items.filter((i) => i.aside === null)}
					{@render entry('/', m.nav_home(), House, page.url.pathname === '/', inView.length, inView.some((i) => i.attention === 'critical'))}
				{/if}
				{#each modules.filter((x) => x.area === 'console') as module (module.id)}
					{@const offered = pagesFor(module, can)}
					{#if offered.length > 0}
						{@const own = concerning(items, module)}
						{@render entry(offered[0]?.path ?? '/', module.label(), module.icon, current === module, own.count, own.critical)}
					{/if}
				{/each}
			</ul>

			<div class="border-t border-border px-3 py-3">
				<ul class="space-y-0.5">
					{#each modules.filter((x) => x.area === 'me') as module (module.id)}
						{@const offered = pagesFor(module, can)}
						{#if offered.length > 0}
							{@render entry(offered[0]?.path ?? '/', module.label(), module.icon, current === module, 0, false)}
						{/if}
					{/each}
				</ul>
				<div class="mt-3 flex items-center justify-between gap-2 px-2 text-xs text-muted-text">
					<span class="min-w-0 truncate" title={person.role_label}>
						{person.account === null ? m.nav_service_token() : m.nav_signed_in_as({ account: person.account })}
					</span>
					{#if !person.by_token}
						<button type="button" class="flex items-center gap-1 hover:text-text" onclick={signOut}>
							<LogOut class="size-3.5" />{m.nav_sign_out()}
						</button>
					{/if}
				</div>
				<div class="mt-2 px-2"><Source /></div>
			</div>
		</nav>

		{#if menuOpen}
			<button
				type="button"
				aria-label={m.nav_close_menu()}
				class="fixed inset-0 z-20 bg-background/60 md:hidden"
				onclick={() => (menuOpen = false)}
			></button>
		{/if}

		<div class="flex min-w-0 flex-1 flex-col">
			<header class="sticky top-0 z-10 border-b border-border bg-background/95 backdrop-blur">
				<div class="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 pt-3 md:px-8">
					<button type="button" class="md:hidden" aria-label={m.nav_open_menu()} onclick={() => (menuOpen = true)}>
						<Menu class="size-5" />
					</button>
					<h1 class="min-w-0 grow basis-32 truncate text-lg font-semibold">
						{current?.label() ?? m.nav_home()}
					</h1>
					{#if unreachable}
						<span role="status" class="rounded-full border border-critical px-2 py-0.5 text-xs font-medium text-critical">
							{m.state_unreachable_short()}
						</span>
					{/if}
				</div>
				{#if tabs.length > 1}
					<nav aria-label={m.nav_sections()} class="-mb-px flex gap-1 overflow-x-auto overflow-y-hidden px-4 md:px-8">
						{#each tabs as tab (tab.path)}
							<a
								href={tab.path}
								aria-current={page.url.pathname === tab.path ? 'page' : undefined}
								class={[
									'border-b-2 px-3 py-2 text-sm whitespace-nowrap',
									page.url.pathname === tab.path
										? 'border-accent font-medium text-text'
										: 'border-transparent text-muted-text hover:text-text'
								]}>{tab.label()}</a
							>
						{/each}
					</nav>
				{:else}
					<div class="h-3"></div>
				{/if}
			</header>

			<!-- The home spans the screen: it is the overview, and a capped width left a third
			     of a wide screen empty beside it. -->
			<main class={['w-full flex-1 px-4 py-6 md:px-8', page.url.pathname !== '/' && 'max-w-6xl']}>
				{@render children()}
			</main>
		</div>
	</div>

	<ActionPanel />
	<CommandPalette {can} bind:open={paletteOpen} />
	{#if helpOpen}
		{@render help()}
	{/if}
{/snippet}

{#snippet entry(href: string, label: string, Icon: typeof House, active: boolean, count: number, critical: boolean)}
	<li>
		<a
			{href}
			aria-current={active ? 'page' : undefined}
			onclick={() => (menuOpen = false)}
			class={[
				'flex items-center gap-3 rounded-md px-3 py-2 text-sm',
				active ? 'bg-raised-surface font-medium text-text' : 'text-muted-text hover:bg-raised-surface hover:text-text'
			]}
		>
			<Icon class="size-4 shrink-0" />
			<span class="min-w-0 flex-1 truncate">{label}</span>
			{#if count > 0}
				<!-- The dot carries how bad; the number stays in the text's colour. Seven red
				     pills down the side said "alarm" seven times and nothing about which. -->
				<span title={m.nav_needs_attention({ count })} class="inline-flex items-center gap-1.5 text-xs tabular-nums">
					<span aria-hidden="true" class={['size-1.5 rounded-full', critical ? 'bg-critical' : 'bg-attention']}></span>{count}
				</span>
			{/if}
		</a>
	</li>
{/snippet}

{#snippet help()}
	<div
		role="dialog"
		aria-label={m.shortcuts_title()}
		class="fixed right-4 bottom-4 z-40 w-72 rounded-xl border border-border bg-surface p-4 text-sm shadow-lg"
	>
		<h2 class="mb-2 font-semibold">{m.shortcuts_title()}</h2>
		<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
			<dt><kbd>Ctrl K</kbd>, <kbd>/</kbd></dt><dd>{m.shortcuts_palette()}</dd>
			<dt><kbd>?</kbd></dt><dd>{m.shortcuts_help()}</dd>
			<dt><kbd>Esc</kbd></dt><dd>{m.shortcuts_close()}</dd>
		</dl>
	</div>
{/snippet}
