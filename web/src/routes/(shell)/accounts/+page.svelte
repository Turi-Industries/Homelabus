<script lang="ts">
	import { proposal, panel } from '#lib/action.svelte.ts';
	import type { Schemas } from '#lib/api/client.ts';
	import { number } from '#lib/format.ts';
	import type { Column, Filter } from '#lib/listing.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import Table from '#lib/ui/Table.svelte';
	import { may } from '#lib/session.ts';
	import { button, input } from '#lib/ui/styles.ts';
	import { ROLE_NAMES, type Role } from '#lib/vocabulary.ts';
	import { accountState } from '#lib/words.ts';

	type Account = Schemas['AccountSummary'];
	const accounts = read('/api/accounts');
	// The roles are data: the selection offers what the roles page keeps.
	const access = read('/api/access');
	// Read outside `Loaded`: watched here, or it is never asked for.
	$effect(() => access.watch());
	// Undefined, the select takes its first role.
	let bulk = $state<string>();

	const address = (a: Account) => (a.mailboxes.find((b) => b.default) ?? a.mailboxes[0])?.address ?? null;
	const role = (a: Account) => a.role_name ?? a.role ?? m.accounts_no_role();
	const level = (a: Account) => ROLE_NAMES[a.level as Role]?.() ?? a.level;

	const columns: Column<Account>[] = [
		{ id: 'name', label: m.accounts_column_name, value: (a) => a.name },
		{ id: 'state', label: m.accounts_column_state, value: (a) => accountState[a.coherence](), cell: state },
		{ id: 'role', label: m.accounts_column_role, value: role },
		{ id: 'address', label: m.accounts_column_mailbox, value: address, wide: true },
		{ id: 'level', label: m.accounts_column_level, value: level, wide: true },
		{ id: 'sessions', label: m.accounts_column_sessions, value: (a) => a.sessions, numeric: true, wide: true },
		{ id: 'aliases', label: m.accounts_column_aliases, value: (a) => a.active_aliases, numeric: true, wide: true, cell: aliases }
	];
	const filters: Filter<Account>[] = [
		{
			id: 'state',
			label: m.accounts_column_state,
			options: [
				// What the warning above the table links to: every half, at once.
				{ value: 'incomplete', label: m.accounts_filter_incomplete },
				...(['complete', 'without-mailbox', 'without-identity', 'empty'] as const).map((s) => ({ value: s, label: accountState[s] }))
			],
			test: (a, v) => (v === 'incomplete' ? a.coherence !== 'complete' : a.coherence === v)
		},
		{
			id: 'level',
			label: m.accounts_column_level,
			options: (Object.keys(ROLE_NAMES) as Role[]).map((r) => ({ value: r, label: ROLE_NAMES[r] })),
			test: (a, v) => a.level === v
		}
	];
</script>

{#snippet state(a: Account)}
	<Mark attention={a.attention} label={accountState[a.coherence]()} />
{/snippet}

<!-- An alias still receiving after its expiry is the promise broken: said in the row. -->
{#snippet aliases(a: Account)}
	{a.active_aliases}
	{#if a.broken_promises > 0}<span class="text-critical">· {m.accounts_still_receiving_badge({ count: a.broken_promises })}</span>{/if}
{/snippet}

<!-- One plan for the whole selection: fifty previews would be fifty confirmations. -->
{#snippet selected(chosen: Account[])}
	{@const roles = access.data?.roles ?? []}
	<select bind:value={bulk} aria-label={m.accounts_column_role()} class={input}>
		{#each roles as r (r.id)}<option value={r.id}>{r.name}</option>{/each}
	</select>
	<button
		type="button"
		class={button}
		disabled={bulk === undefined}
		onclick={() =>
			panel.propose(
				proposal(
					m.accounts_selection_title({ count: number(chosen.length), role: roles.find((r) => r.id === bulk)?.name ?? bulk ?? '' }),
					'post',
					'/api/accounts/role/{role}',
					{ path: { role: bulk ?? '' }, body: { accounts: chosen.map((a) => a.name) } }
				)
			)}>{m.accounts_selection_role()}</button
	>
{/snippet}

<Loaded resource={accounts}>
	{#snippet children(list)}
		{@const incomplete = list.filter((a) => a.coherence !== 'complete').length}
		{@const broken = list.reduce((n, a) => n + a.broken_promises, 0)}
		{#if incomplete > 0}
			<p class="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
				<span class="text-critical">{m.accounts_incomplete_count({ count: incomplete })}</span>
				<span class="min-w-0 grow basis-64 text-muted-text">{m.accounts_incomplete_explanation()}</span>
				<a href="/accounts?state=incomplete" class="text-accent hover:underline">{m.accounts_show_incomplete()}</a>
			</p>
		{/if}
		{#if broken > 0}
			<p class="mb-3 text-sm">
				<span class="text-critical">{m.accounts_still_receiving_count({ count: broken })}</span>
				<span class="text-muted-text">{m.accounts_broken_promise_explanation()}</span>
			</p>
		{/if}
		<Table
			rows={list}
			key={(a) => a.name}
			{columns}
			{filters}
			href={(a) => `/accounts/${a.name}`}
			search={m.accounts_search()}
			empty={m.accounts_none()}
			selection={may('/api/accounts/role/{role}', 'POST') ? selected : undefined}
		>
			{#snippet actions()}<a href="/api/export/accounts" download class={button}>{m.export_csv()}</a>{/snippet}
		</Table>
	{/snippet}
</Loaded>
