<script lang="ts">
	import { limits } from '#lib/api/limits.ts';
	import { proposal, panel } from '#lib/action.svelte.ts';
	import type { Schemas } from '#lib/api/client.ts';
	import { bytes, GIB } from '#lib/format.ts';
	import type { Column } from '#lib/listing.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Table from '#lib/ui/Table.svelte';
	import { button, input, muted, primary } from '#lib/ui/styles.ts';
	import { ROLE_NAMES, ROLES, type Role } from '#lib/vocabulary.ts';

	type RoleRow = Schemas['RoleSummary'];
	type AppRow = Schemas['AppAccess'];
	const access = read('/api/access');

	// One form for a new role and for changing one: the id is fixed once it exists.
	let editing = $state<{ id: string; name: string; level: Role; fresh: boolean } | undefined>();
	let editOpen = $state(false);
	// A role's quota in one app.
	let quota = $state<{ role: string; app: string; gib: number; none: boolean } | undefined>();
	let quotaOpen = $state(false);
	// The role being let into each app, by app.
	let letting = $state<Record<string, string>>({});

	const idPattern = '[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?';

	function edit(r?: RoleRow) {
		editing = r
			? { id: r.id, name: r.name, level: r.level as Role, fresh: false }
			: { id: '', name: '', level: 'user', fresh: true };
		editOpen = true;
	}

	function setQuota(r: RoleRow, apps: AppRow[]) {
		const app = apps.find((a) => a.quota)?.app ?? '';
		const current = r.quotas[app];
		quota = { role: r.id, app, gib: current ? current / GIB : 50, none: current === undefined };
		quotaOpen = true;
	}

	const roleColumns: Column<RoleRow>[] = [
		{ id: 'name', label: m.roles_column_name, value: (r) => r.name, cell: named },
		{ id: 'level', label: m.roles_column_level, value: (r) => ROLE_NAMES[r.level as Role]?.() ?? r.level },
		{ id: 'holders', label: m.roles_column_holders, value: (r) => r.holders.length, numeric: true },
		{ id: 'apps', label: m.roles_column_apps, value: (r) => r.apps.join(', '), wide: true },
		{ id: 'quotas', label: m.roles_column_quotas, value: (r) => Object.keys(r.quotas).length, cell: quotas, wide: true },
		{ id: 'actions', label: m.roles_column_actions, cell: actions }
	];

	const appColumns: Column<AppRow>[] = [
		{ id: 'app', label: m.roles_column_app, value: (a) => a.display_name },
		{ id: 'state', label: m.roles_column_state, value: (a) => (a.closed ? 0 : 1), cell: door, wide: true },
		{ id: 'floor', label: m.roles_column_floor, value: (a) => ROLE_NAMES[a.floor as Role]?.() ?? a.floor, wide: true },
		{ id: 'allowed', label: m.roles_column_allowed, cell: allowed }
	];
</script>

{#snippet named(r: RoleRow)}
	<span class="font-medium">{r.name}</span>
	{#if r.name !== r.id}<span class="ml-1 font-mono text-xs text-muted-text">{r.id}</span>{/if}
	<!-- What giving it opens, where it is given. -->
	{#each r.opens as o (o.app)}
		<span class="block text-xs text-attention">{m.roles_administers({ app: o.display_name, means: o.means })}</span>
	{/each}
{/snippet}

{#snippet quotas(r: RoleRow)}
	{#each Object.entries(r.quotas) as [app, b] (app)}
		<span class="block whitespace-nowrap">{app} · {bytes(b)}</span>
	{:else}
		<span class="text-muted-text">—</span>
	{/each}
{/snippet}

{#snippet actions(r: RoleRow)}
	{@const apps = access.data?.apps ?? []}
	<span class="flex flex-wrap gap-x-3 gap-y-1 text-sm">
		{#if may('/api/roles/{role}', 'POST')}
			<button type="button" class="text-accent hover:underline" onclick={() => edit(r)}>{m.roles_edit()}</button>
		{/if}
		{#if may('/api/roles/{role}/quota/{app}', 'POST') && apps.some((a) => a.quota)}
			<button type="button" class="text-accent hover:underline" onclick={() => setQuota(r, apps)}>{m.roles_quota()}</button>
		{/if}
		{#if may('/api/roles/{role}', 'DELETE')}
			<button
				type="button"
				class="text-critical hover:underline"
				onclick={() => panel.propose(proposal(m.roles_delete_title({ role: r.name }), 'delete', '/api/roles/{role}', { path: { role: r.id } }))}
				>{m.roles_delete()}</button
			>
		{/if}
	</span>
{/snippet}

{#snippet door(a: AppRow)}
	<Mark
		attention={a.closed ? 'critical' : 'ok'}
		label={a.closed ? m.roles_closed() : a.entry === 'portal' ? m.roles_open_portal() : m.roles_open_client()}
	/>
{/snippet}

{#snippet allowed(a: AppRow)}
	{@const roles = access.data?.roles ?? []}
	<span class="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
		<!-- Said here too: on a phone the state's own column is gone. -->
		{#if a.closed}<span class="md:hidden"><Mark attention="critical" label={m.roles_closed()} /></span>{/if}
		{#each a.allowed as id (id)}
			{@const role = roles.find((r) => r.id === id)}
			<span class="whitespace-nowrap">
				{role?.name ?? id}
				{#if may('/api/apps/{app}/roles/{role}', 'DELETE')}
					<button
						type="button"
						class="text-critical hover:underline"
						aria-label={m.roles_deny_title({ role: role?.name ?? id, app: a.display_name })}
						onclick={() =>
							panel.propose(
								proposal(m.roles_deny_title({ role: role?.name ?? id, app: a.display_name }), 'delete', '/api/apps/{app}/roles/{role}', {
									path: { app: a.app, role: id }
								})
							)}>×</button
					>
				{/if}
			</span>
		{/each}
		{#if may('/api/apps/{app}/roles/{role}', 'POST')}
			{@const others = roles.filter((r) => !a.allowed.includes(r.id))}
			{#if others.length > 0}
				<span class="flex gap-1">
					<select bind:value={letting[a.app]} aria-label={m.roles_let_in({ app: a.display_name })} class={input}>
						{#each others as r (r.id)}<option value={r.id}>{r.name}</option>{/each}
					</select>
					<button
						type="button"
						class={button}
						onclick={() => {
							const id = letting[a.app] ?? others[0]?.id;
							if (id === undefined) return;
							const name = roles.find((r) => r.id === id)?.name ?? id;
							void panel.propose(
								proposal(m.roles_allow_title({ role: name, app: a.display_name }), 'post', '/api/apps/{app}/roles/{role}', {
									path: { app: a.app, role: id }
								})
							);
						}}>{m.roles_let_in_button()}</button
					>
				</span>
			{/if}
		{/if}
	</span>
{/snippet}

<Loaded resource={access}>
	{#snippet children(o)}
		<div class="flex flex-col gap-6">
			<div class="flex flex-wrap items-center gap-3">
				{#if may('/api/roles/{role}', 'POST')}
					<button type="button" class={primary} onclick={() => edit()}>{m.roles_new()}</button>
				{/if}
				{#if may('/api/access/sync', 'POST')}
					<button type="button" class={button} onclick={() => panel.propose(proposal(m.roles_sync_title(), 'post', '/api/access/sync'))}
						>{m.roles_sync()}</button
					>
				{/if}
				<p class="min-w-0 grow basis-64 {muted}">{m.roles_explanation()}</p>
			</div>

			{#if o.notes.length > 0}
				<Card title={m.roles_notes()}>
					<ul class="list-disc space-y-1 pl-5 text-sm">{#each o.notes as n, i (i)}<li>{n}</li>{/each}</ul>
				</Card>
			{/if}

			<section>
				<h2 class="mb-2 font-semibold">{m.roles_heading_roles()}</h2>
				<Table rows={o.roles} key={(r) => r.id} columns={roleColumns} filters={[]} search={m.roles_search()} empty={m.roles_none()} />
			</section>

			<section>
				<h2 class="mb-2 font-semibold">{m.roles_heading_apps()}</h2>
				<p class="mb-2 {muted}">{m.roles_apps_explanation({ count: o.apps.filter((a) => a.closed).length })}</p>
				<Table rows={o.apps} key={(a) => a.app} columns={appColumns} filters={[]} search={m.roles_search_apps()} empty={m.roles_no_app()} />
			</section>
		</div>
	{/snippet}
</Loaded>

<Modal bind:open={editOpen} title={editing?.fresh ? m.roles_new() : m.roles_edit()}>
	{#if editing}
		<form
			class="flex flex-col gap-3"
			onsubmit={(e) => {
				e.preventDefault();
				if (!editing) return;
				const { id, name, level } = editing;
				editOpen = false;
				void panel.propose(
					proposal(m.roles_set_title({ role: name === '' ? id : name }), 'post', '/api/roles/{role}', {
						path: { role: id },
						body: { name: name === '' ? null : name, level, mail: null }
					})
				);
			}}
		>
			<label class="flex flex-col gap-1 text-sm">{m.roles_id()}
				<input
					bind:value={editing.id}
					required
					disabled={!editing.fresh}
					pattern={idPattern}
					maxlength={limits.InvitationRequest.role.maxLength}
					class="{input} font-mono"
				/>
				<span class="text-xs text-muted-text">{m.roles_id_explanation()}</span>
			</label>
			<label class="flex flex-col gap-1 text-sm">{m.roles_name()}
				<input bind:value={editing.name} minlength="2" maxlength={limits.RoleRequest.name.maxLength} class={input} />
			</label>
			<label class="flex flex-col gap-1 text-sm">{m.roles_column_level()}
				<select bind:value={editing.level} class={input}>{#each Object.entries(ROLES) as [r, label] (r)}<option value={r}>{label()}</option>{/each}</select>
			</label>
			{#if editing.level === 'admin'}
				<p class="text-sm text-critical"><span class="font-semibold">{m.accounts_admin_role()}</span> — {m.accounts_admin_role_explanation()}</p>
			{/if}
			<button type="submit" class={primary}>{m.roles_preview()}</button>
		</form>
	{/if}
</Modal>

<Modal bind:open={quotaOpen} title={m.roles_quota()}>
	{#if quota && access.data}
		{@const takers = access.data.apps.filter((a) => a.quota)}
		<form
			class="flex flex-col gap-3"
			onsubmit={(e) => {
				e.preventDefault();
				if (!quota) return;
				const { role, app, gib, none } = quota;
				quotaOpen = false;
				void panel.propose(
					proposal(m.roles_quota_title({ role, app }), 'post', '/api/roles/{role}/quota/{app}', {
						path: { role, app },
						body: { bytes: none ? null : Math.round(gib * GIB) }
					})
				);
			}}
		>
			<label class="flex flex-col gap-1 text-sm">{m.roles_column_app()}
				<select bind:value={quota.app} class={input}>{#each takers as a (a.app)}<option value={a.app}>{a.display_name}</option>{/each}</select>
			</label>
			<label class="flex items-center gap-2 text-sm"><input type="checkbox" bind:checked={quota.none} />{m.roles_quota_none()}</label>
			{#if !quota.none}
				<label class="flex flex-col gap-1 text-sm">{m.roles_quota_gib()}
					<input type="number" min="1" max={limits.QuotaRequest.bytes.maximum / GIB} step="1" required bind:value={quota.gib} class="{input} w-28" />
				</label>
			{/if}
			<button type="submit" class={primary}>{m.roles_preview()}</button>
		</form>
	{/if}
</Modal>
