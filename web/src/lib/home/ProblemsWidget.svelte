<script lang="ts">
	import { api } from '#lib/api/client.ts';
	import { number, when } from '#lib/format.ts';
	import { lines, type Line } from '#lib/inbox.svelte.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read, refusal } from '#lib/resource.svelte.ts';
	import { me } from '#lib/session.ts';
	import Modal from '#lib/ui/Modal.svelte';
	import { button } from '#lib/ui/styles.ts';
	import { tone } from '#lib/words.ts';

	/**
	 * Every line of the inbox, the worst first: the home's one list of what needs
	 * someone. All of them, scrolled inside the tile — a home that showed eight and
	 * folded the rest made the ninth the one nobody opened.
	 */
	const words = { notice: m.attention_notice, critical: m.attention_critical };
	const person = $derived(me().data);
	const issues = read('/api/issues');
	$effect(() => issues.watch());
	const all = $derived(lines(issues.data ?? []));
	const open = $derived(all.filter((l) => l.aside === null));
	const aside = $derived(all.filter((l) => l.aside !== null));
	const waiting = $derived(issues.data === undefined && issues.error === undefined);

	// A service token belongs to nobody: it has no inbox of its own to arrange.
	const ownsInbox = $derived(person?.account !== null && person?.account !== undefined);
	let asideError = $state<string | undefined>();
	// The line "later" was asked of; the modal closes by clearing the boolean beside it.
	let deferring = $state.raw<Line | undefined>();
	let asking = $state(false);

	async function setAside(line: Line, seconds: number) {
		asking = false;
		const { error, response } = await api.PUT('/api/issues/aside', { body: { cause: line.issue.cause, for_s: seconds } });
		asideError = response.ok ? undefined : m.inbox_aside_failed({ error: refusal(error, response) });
		await issues.refresh();
	}

	async function bringBack(line: Line) {
		const { error, response } = await api.DELETE('/api/issues/aside', { body: { cause: line.issue.cause } });
		asideError = response.ok ? undefined : m.inbox_aside_failed({ error: refusal(error, response) });
		await issues.refresh();
	}
</script>

<section aria-labelledby="inbox-title" class="flex h-full min-h-0 min-w-0 flex-col rounded-lg border border-border bg-surface">
	<header class="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 pt-3 pb-1">
		<h2 id="inbox-title" class="text-sm font-semibold">{m.inbox_title()}</h2>
		{#if open.length > 0}
			<span class="text-xs text-muted-text">{m.nav_needs_attention({ count: open.length })}</span>
		{/if}
	</header>

	<!-- `relative`: a screen reader's words are absolutely placed, and without a placed
	     ancestor in here they escape the scrolling and lengthen the page by its list. -->
	<div class="relative min-h-0 flex-1 overflow-y-auto px-1 pb-2">
		{#if issues.error !== undefined}
			<p role="alert" class="mx-3 mb-2 rounded-lg border border-critical p-3 text-sm text-critical">
				{m.inbox_incomplete({ error: issues.error })}
			</p>
		{/if}
		{#if asideError}<p role="alert" class="mx-3 mb-2 text-sm text-critical">{asideError}</p>{/if}

		{#if open.length === 0}
			<p class="px-3 py-2 text-sm text-muted-text" aria-busy={waiting}>
				{#if waiting}{m.inbox_waiting()}{:else if issues.error === undefined}{m.inbox_all_clear()}{/if}
			</p>
		{:else}
			<ul class="divide-y divide-border">
				{#each open as line (JSON.stringify(line.issue.cause))}
					{@render row(line)}
				{/each}
			</ul>
		{/if}

		<!-- 🔴 A line set aside stays LISTED, folded: hiding a problem someone deferred is
		     how it is forgotten. -->
		{#if aside.length > 0}
			<details class="mx-3 mt-2">
				<summary class="cursor-pointer text-sm text-muted-text">
					{m.inbox_aside_title({ count: aside.length, shown: number(aside.length) })}
				</summary>
				<ul class="mt-1 divide-y divide-border">
					{#each aside as line (JSON.stringify(line.issue.cause))}
						{@render row(line)}
					{/each}
				</ul>
			</details>
		{/if}
	</div>
</section>

{#if deferring !== undefined}
	{@const later = deferring}
	<Modal bind:open={asking} title={m.inbox_later_title({ title: later.title })}>
		<div class="flex flex-col gap-2">
			<button type="button" class={button} onclick={() => setAside(later, 86_400)}>{m.inbox_until_tomorrow()}</button>
			<button type="button" class={button} onclick={() => setAside(later, 7 * 86_400)}>{m.inbox_for_a_week()}</button>
		</div>
	</Modal>
{/if}

<!-- A line: what, what it covers, where it belongs — and, for a person, "later". The
     link and the buttons are apart: a row carrying a button is not also a click target. -->
{#snippet row(line: Line)}
	<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
		<span aria-hidden="true" class={['size-2 shrink-0 rounded-full', tone[line.attention].bg]}></span>
		<a href={line.href} class="flex min-w-0 grow basis-48 flex-col hover:underline">
			<span class="text-sm font-medium">{line.title}<span class="sr-only"> — {words[line.attention]()}</span></span>
			{#if line.detail}<span class="truncate text-xs text-muted-text" title={line.detail}>{line.detail}</span>{/if}
		</a>
		{#if line.module}<span class="hidden text-xs text-muted-text xl:inline">{line.module.label()}</span>{/if}
		{#if ownsInbox}
			{#if line.aside !== null}
				<span class="text-xs text-muted-text">{m.inbox_aside_until({ at: when(line.aside) })}</span>
				<button type="button" class={[button, 'py-0.5 text-xs']} onclick={() => bringBack(line)}>{m.inbox_bring_back()}</button>
			{:else}
				<button
					type="button"
					class="rounded-md px-2 py-0.5 text-xs text-muted-text hover:bg-raised-surface hover:text-text"
					onclick={() => ((deferring = line), (asking = true))}>{m.inbox_later()}</button
				>
			{/if}
		{/if}
	</li>
{/snippet}
