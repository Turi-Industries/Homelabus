<script lang="ts">
	import { limits } from '#lib/api/limits.ts';
	import { proposal, panel } from '#lib/action.svelte.ts';
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import type { Schemas } from '#lib/api/client.ts';
	import type { Column, Filter } from '#lib/listing.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Table from '#lib/ui/Table.svelte';
	import { input, primary } from '#lib/ui/styles.ts';
	import { ROLE_NAMES, type Role } from '#lib/vocabulary.ts';

	type Invitation = Schemas['InvitationSummary'];
	const invitations = read('/api/invitations');
	// The roles a link may grant: data, as the roles page keeps them.
	const access = read('/api/access');
	// Read outside `Loaded`: watched here, or it is never asked for.
	$effect(() => access.watch());
	const roleName = (id: string) => access.data?.roles.find((r) => r.id === id)?.name ?? id;
	const states = {
		pending: m.people_invitation_state_pending,
		partly_used: m.people_invitation_state_partly_used,
		exhausted: m.people_invitation_state_exhausted,
		expired: m.people_invitation_state_expired
	};

	const columns: Column<Invitation>[] = [
		{ id: 'state', label: m.invitations_column_state, value: (i) => states[i.state](), cell: state },
		{ id: 'for', label: m.invitations_column_for, value: (i) => roleName(i.role), wide: true },
		{ id: 'by', label: m.invitations_column_by, value: (i) => i.created_by, wide: true },
		{ id: 'left', label: m.invitations_column_left, value: (i) => (i.usable ? i.expires_in_s : null), cell: left },
		{ id: 'note', label: m.invitations_column_note, value: (i) => i.note, wide: true },
		{ id: 'revoke', label: m.invitations_column_action, cell: revoke }
	];
	const filters: Filter<Invitation>[] = [
		{
			id: 'state',
			label: m.invitations_column_state,
			options: (Object.keys(states) as Invitation['state'][]).map((s) => ({ value: s, label: states[s] })),
			test: (i, v) => i.state === v
		}
	];

	let creating = $state(false);
	// Undefined, the select takes its first role.
	let role = $state<string>();
	const chosen = $derived(access.data?.roles.find((r) => r.id === role));
	let uses = $state(1);
	// One value, asked once: a number and its unit, said by one formatter.
	let amount = $state(7);
	let unit = $state<'h' | 'd'>('d');
	let note = $state('');
	const per = $derived(unit === 'h' ? 3_600 : 86_400);
	const seconds = $derived(amount * per);
	// The controller's bounds, said in the unit chosen: 1 to 720 hours, 1 to 30 days.
	const bounds = limits.InvitationRequest;
	const fewest = $derived(Math.ceil(bounds.duration_s.minimum / per));
	const most = $derived(Math.floor(bounds.duration_s.maximum / per));
	const valid = $derived(
		Number.isInteger(amount) && amount >= fewest && amount <= most &&
			Number.isInteger(uses) && uses >= bounds.max_uses.minimum && uses <= bounds.max_uses.maximum &&
			chosen !== undefined
	);
</script>

<!-- A link open to several people is the one forgotten open: said in its row. -->
{#snippet state(i: Invitation)}
	<span
		class={['whitespace-nowrap', i.usable && i.widely_open ? 'text-attention' : i.usable ? undefined : 'text-muted-text']}
		title={i.usable && i.widely_open ? m.people_widely_open() : undefined}
	>
		{states[i.state]()}{#if i.usable && i.widely_open}{' · '}{m.invitations_widely_open({ count: i.max_uses })}{/if}
	</span>
{/snippet}

{#snippet left(i: Invitation)}
	<span class={['whitespace-nowrap', i.usable ? undefined : 'text-muted-text']}>
		{i.usable ? m.invitations_left({ remaining: i.remaining, expires_in: duration(i.expires_in_s) }) : m.accounts_kept_as_a_trace()}
	</span>
{/snippet}

{#snippet revoke(i: Invitation)}
	{#if i.usable && may('/api/invitations/{reference}', 'DELETE')}
		<button
			type="button"
			class="text-sm text-critical hover:underline"
			onclick={() =>
				panel.propose(proposal(m.people_revoke_title({ reference: i.reference }), 'delete', '/api/invitations/{reference}', { path: { reference: i.reference } }))}
			>{m.accounts_revoke()}</button
		>
	{/if}
{/snippet}

<div>
	{#if may('/api/invitations', 'POST')}
		<button type="button" class={[primary, 'mb-4']} onclick={() => (creating = true)}>{m.people_new_invitation()}</button>
		<Modal bind:open={creating} title={m.people_new_invitation()}>
			<form
				class="flex flex-col gap-3"
				onsubmit={(e) => {
					e.preventDefault();
					// The modal gives way to the preview; what was typed stays for a second try.
					creating = false;
					void panel.propose(
						proposal(m.people_invite_title({ role: chosen?.name ?? role ?? '' }), 'post', '/api/invitations', {
							body: { role, max_uses: uses, duration_s: seconds, note: note.trim() === '' ? null : note.trim() }
						})
					);
				}}
			>
				<label class="flex flex-col gap-1 text-sm">{m.accounts_role()}
					<select bind:value={role} required class={input}>
						{#each access.data?.roles ?? [] as r (r.id)}
							<option value={r.id}>{m.roles_choice({ name: r.name, level: ROLE_NAMES[r.level as Role]?.() ?? r.level })}</option>
						{/each}
					</select>
				</label>
				{#if chosen?.level === 'admin'}
					<p class="text-sm text-critical"><span class="font-semibold">{m.accounts_admin_role()}</span> — {m.accounts_admin_role_explanation()}</p>
				{/if}
				{#each chosen?.opens ?? [] as o (o.app)}
					<p class="text-sm text-attention">{m.roles_administers({ app: o.display_name, means: o.means })}</p>
				{/each}
				<div class="flex flex-wrap gap-3">
					<label class="flex flex-col gap-1 text-sm">{m.accounts_valid_for()}
						<span class="flex gap-1">
							<input type="number" min={fewest} max={most} step="1" required bind:value={amount} class={[input, 'w-20']} />
							<select bind:value={unit} class={input} aria-label={m.accounts_valid_for()}>
								<option value="h">{m.accounts_unit_hour()}</option>
								<option value="d">{m.accounts_unit_day()}</option>
							</select>
						</span>
					</label>
					<label class="flex flex-col gap-1 text-sm">{m.accounts_people()}
						<input type="number" min={bounds.max_uses.minimum} max={bounds.max_uses.maximum} step="1" required bind:value={uses} class={[input, 'w-20']} />
					</label>
				</div>
				{#if !valid}
					<p class="text-sm text-critical">
						{chosen === undefined
							? m.invitations_choose_role()
							: amount < fewest || amount > most || !Number.isInteger(amount)
							? `${m.accounts_valid_for()} — ${m.field_between({ min: fewest, max: most })}`
							: `${m.accounts_people()} — ${m.field_between({ min: bounds.max_uses.minimum, max: bounds.max_uses.maximum })}`}
					</p>
				{/if}
				{#if uses > 1}
					<p class="text-sm text-attention">{m.accounts_link_will_let_in({ count: uses })} {m.accounts_link_leak_explanation()}</p>
				{/if}
				<input bind:value={note} maxlength={bounds.note.maxLength} placeholder={m.people_note_hint()} aria-label={m.people_note_hint()} class={input} />
				<button type="submit" class={primary} disabled={!valid}>{m.accounts_create_the_link()}</button>
			</form>
		</Modal>
	{/if}

	<Loaded resource={invitations}>
		{#snippet children(list)}
			<Table
				rows={list}
				key={(i) => i.reference}
				{columns}
				{filters}
				search={m.invitations_search()}
				empty={m.people_no_invitation()}
			/>
		{/snippet}
	</Loaded>
</div>
