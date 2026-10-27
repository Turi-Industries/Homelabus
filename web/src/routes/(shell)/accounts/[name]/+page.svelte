<script lang="ts">
	import { page } from '$app/state';
	import { proposal, panel } from '#lib/action.svelte.ts';
	import { api, type Schemas } from '#lib/api/client.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read, refusal } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Gone from '#lib/ui/Gone.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import { button, code, input, muted, primary } from '#lib/ui/styles.ts';
	import { bytes, GIB, when } from '#lib/format.ts';
	import { limits } from '#lib/api/limits.ts';
	import { ROLE_NAMES, type Role } from '#lib/vocabulary.ts';
	import { accountExplanation } from '#lib/words.ts';

	const name = $derived(page.params.name ?? '');
	// The list, not a route of its own: one read the list page already shares, and a
	// person found here is the same row the list shows.
	const accounts = read('/api/accounts');
	// The roles are data, as the roles page keeps them.
	const access = read('/api/access');
	// Read outside `Loaded`: watched here, or it is never asked for.
	$effect(() => access.watch());
	let role = $state<string | undefined>();
	// A person's own quota in one app: a size, none at all, or their role's again.
	let own = $state<{ app: string; kind: 'bytes' | 'none' | 'role'; gib: number } | undefined>();
	let ownOpen = $state(false);
	// The token exists only in this answer: kept in memory for this page, never stored.
	let bitwarden = $state<{ settings?: Schemas['Settings']; error?: string } | undefined>();
	let showing = $state(false);

	async function setUpBitwarden() {
		bitwarden = undefined;
		showing = true;
		const { data, error, response } = await api.POST('/api/bitwarden', { body: { account: name, mailbox: null, name: null } });
		bitwarden = data ? { settings: data } : { error: m.me_bitwarden_failed({ error: refusal(error, response) }) };
	}
</script>

<Loaded resource={accounts}>
	{#snippet children(list)}
		{@const a = list.find((x) => x.name === name)}
		{#if a === undefined}
			<Gone back="/accounts" />
		{:else}
			<PageHeader title={a.name}>
				{#snippet meta()}{a.role_name ?? a.role ?? m.accounts_no_role()} · {ROLE_NAMES[a.level as Role]?.() ?? a.level}{/snippet}
				{#snippet actions()}
					{#if a.mailboxes.length > 0 && may('/api/bitwarden', 'POST')}
						<button type="button" class={button} onclick={setUpBitwarden}>{m.me_bitwarden()}</button>
					{/if}
				{/snippet}
			</PageHeader>

			<div class="grid gap-4 lg:grid-cols-2">
				{#if a.coherence !== 'complete'}
					<Card title={m.accounts_detail_repair()}>
						<p class="text-sm">{accountExplanation[a.coherence]()}</p>
						{#if a.remedy}<code class="mt-3 block {code}">{a.remedy}</code>{/if}
					</Card>
				{/if}

				<Card title={m.accounts_detail_mailboxes()}>
					{#if a.broken_promises > 0}
						<p class="mb-2 text-sm text-critical">{m.accounts_still_receiving_badge({ count: a.broken_promises })}</p>
					{/if}
					<ul class="text-sm">
						{#each a.mailboxes as box (box.address)}
							<li>{m.accounts_default_mailbox({ is_default: box.default ? '1' : '0', address: box.address })}</li>
						{/each}
					</ul>
					<p class="mt-2 {muted}">
						{m.accounts_active_alias_count({ count: a.active_aliases })}
						· {m.accounts_session_count({ count: a.sessions })}
					</p>
				</Card>

				<Card title={m.accounts_detail_role()}>
					<p class="text-sm">
						{m.accounts_detail_identity()} :
						{a.pocket_id ? m.accounts_pocket_id_reference({ id: a.pocket_id }) : m.accounts_detail_none()}
					</p>
					{#if may('/api/accounts/{account}/role/{role}', 'POST')}
						<form
							class="mt-3 flex flex-wrap items-center gap-2"
							onsubmit={(e) => {
								e.preventDefault();
								if (role === undefined) return;
								const name = access.data?.roles.find((r) => r.id === role)?.name ?? role;
								void panel.propose(
									proposal(m.people_role_title({ account: a.name, role: name }), 'post', '/api/accounts/{account}/role/{role}', {
										path: { account: a.name, role }
									})
								);
							}}
						>
							<select bind:value={role} aria-label={m.people_role_change()} class={input}>
								{#each access.data?.roles ?? [] as r (r.id)}
									<option value={r.id} disabled={r.id === a.role}>{m.roles_choice({ name: r.name, level: ROLE_NAMES[r.level as Role]?.() ?? r.level })}</option>
								{/each}
							</select>
							<button type="submit" class={button} disabled={role === undefined}>{m.people_role_change()}</button>
						</form>
					{/if}
				</Card>

				{#if a.quotas.length > 0}
					<Card title={m.accounts_detail_quotas()}>
						<ul class="flex flex-col gap-2 text-sm">
							{#each a.quotas as q (q.app)}
								<li class="flex flex-wrap items-baseline gap-x-3 gap-y-1">
									<span class="font-medium">{q.app}</span>
									<span>{q.bytes === null ? m.accounts_quota_none() : bytes(q.bytes)}</span>
									<span class="min-w-0 grow basis-48 {muted}">
										{q.own
											? m.accounts_quota_own({ by: q.set_by ?? '?', at: q.set_at ? when(q.set_at) : '?' })
											: m.accounts_quota_role()}
										{#if q.state === 'absent'} · {m.accounts_quota_absent()}{:else if q.state === 'failed'} · <span class="text-critical">{q.detail ?? m.accounts_quota_failed()}</span>{/if}
									</span>
									{#if may('/api/accounts/{account}/quota/{app}', 'POST')}
										<button
											type="button"
											class="text-accent hover:underline"
											onclick={() => {
												own = { app: q.app, kind: q.own ? (q.bytes === null ? 'none' : 'bytes') : 'bytes', gib: q.bytes === null ? 50 : q.bytes / GIB };
												ownOpen = true;
											}}>{m.accounts_quota_change()}</button
										>
									{/if}
								</li>
							{/each}
						</ul>
					</Card>
				{/if}
			</div>
		{/if}
	{/snippet}
</Loaded>

<!-- Over the page, beside the button that asked: the key is shown this once, and drawn in
     a card further down it went unseen. -->
<Modal bind:open={showing} title={m.me_bitwarden_title()}>
	{#if bitwarden === undefined}
		<p class="text-sm text-muted-text" aria-busy="true">{m.state_loading()}</p>
	{:else if bitwarden.error}
		<p role="alert" class="text-sm text-critical">{bitwarden.error}</p>
	{:else if bitwarden.settings}
		{@const s = bitwarden.settings}
		<dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 rounded-lg border border-accent p-3 text-sm">
			<dt class="text-muted-text">{m.me_bitwarden_server()}</dt><dd class="font-mono text-xs break-all">{s.server_url}</dd>
			<dt class="text-muted-text">{m.me_bitwarden_domain()}</dt><dd class="font-mono text-xs">{s.domain}</dd>
			<dt class="col-span-2 text-muted-text">{m.me_bitwarden_token({ name: s.token_name })}</dt>
			<dd class="col-span-2 font-mono text-xs break-all">{s.token}</dd>
		</dl>
		<ol class="list-decimal space-y-1 pl-5 text-sm">{#each s.steps as step, i (i)}<li>{step}</li>{/each}</ol>
	{/if}
</Modal>

<Modal bind:open={ownOpen} title={m.accounts_quota_change()}>
	{#if own}
		<form
			class="flex flex-col gap-3"
			onsubmit={(e) => {
				e.preventDefault();
				if (!own) return;
				const { app, kind, gib } = own;
				ownOpen = false;
				void panel.propose(
					proposal(m.accounts_quota_title({ account: name, app }), 'post', '/api/accounts/{account}/quota/{app}', {
						path: { account: name, app },
						body: kind === 'bytes' ? { bytes: Math.round(gib * GIB), none: false } : { bytes: null, none: kind === 'none' }
					})
				);
			}}
		>
			<p class="text-sm font-medium">{own.app}</p>
			<label class="flex items-center gap-2 text-sm"><input type="radio" bind:group={own.kind} value="bytes" />{m.roles_quota_gib()}</label>
			{#if own.kind === 'bytes'}
				<input
					type="number"
					min="1"
					max={limits.PersonQuotaRequest.bytes.maximum / GIB}
					step="1"
					required
					bind:value={own.gib}
					aria-label={m.roles_quota_gib()}
					class="{input} w-28"
				/>
			{/if}
			<label class="flex items-center gap-2 text-sm"><input type="radio" bind:group={own.kind} value="none" />{m.roles_quota_none()}</label>
			<label class="flex items-center gap-2 text-sm"><input type="radio" bind:group={own.kind} value="role" />{m.accounts_quota_back_to_role()}</label>
			<button type="submit" class={primary}>{m.roles_preview()}</button>
		</form>
	{/if}
</Modal>
