<script lang="ts">
	import { panel, proposal } from '#lib/action.svelte.ts';
	import { limits } from '#lib/api/limits.ts';
	import type { Schemas } from '#lib/api/client.ts';
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may, me } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { button, code, input, muted, primary } from '#lib/ui/styles.ts';

	const who = me();
	const identity = read('/api/me/identity');
	const sessions = read('/api/me/sessions');
	const rights = [
		['read_self', m.my_account_can_read_self],
		['act_on_self', m.my_account_can_act_on_self],
		['read', m.my_account_can_read],
		['publish', m.my_account_can_publish],
		['operate', m.my_account_can_operate],
		['manage_accounts', m.my_account_can_manage_accounts],
		['destroy', m.my_account_can_destroy]
	] as const;

	type Names = Required<Schemas['NamesRequest']>;
	// What the person typed, apart from what was read: the identity is polled, and a
	// field bound to the answer would be put back under their fingers every few seconds.
	let draft = $state.raw<Names | undefined>();
	let chosen = $state<string | undefined>();

	function namesOf(i: Schemas['MyIdentity']): Names {
		return { first_name: i.first_name ?? '', last_name: i.last_name ?? '', display_name: i.display_name ?? '' };
	}

	const unlinked: Record<Exclude<Schemas['IdentityLink'], 'linked'>, () => string> = {
		'not-configured': m.my_account_identity_not_configured,
		'not-linked': m.my_account_identity_not_linked,
		unreachable: m.my_account_identity_unreachable
	};

	function device(s: Schemas['MySession']): string {
		return s.user_agent ?? m.my_account_unknown_device();
	}
</script>

<Loaded resource={who}>
	{#snippet children(person)}
		<div class="grid gap-4 lg:grid-cols-2">
			<Card title={person.account ?? m.nav_service_token()}>
				{#if person.account === null}
					<p class={muted}>{m.my_account_service_token_explanation()}</p>
					<code class="mt-2 block {code}">{m.my_account_service_token_command()}</code>
				{:else}
					<p class="text-sm">{person.role} — {person.role_label}</p>
					<h3 class="mt-4 mb-1 text-sm font-semibold">{m.my_account_my_addresses()}</h3>
					{#if person.mailboxes.length === 0}<p class={muted}>{m.my_account_no_mailbox()}</p>{/if}
					<ul class="text-sm">
						{#each person.mailboxes as box (box.address)}<li>{box.address} {#if box.default}<span class="text-muted-text">· {m.my_account_default_mailbox()}</span>{/if}</li>{/each}
					</ul>
					{#if person.mailboxes.length > 1 && may('/api/me/default-mailbox', 'PUT')}
						{@const current = person.mailboxes.find((b) => b.default)?.address}
						{@const picked = chosen ?? current}
						<form
							class="mt-4 flex flex-wrap items-end gap-2"
							onsubmit={(e) => {
								e.preventDefault();
								if (picked === undefined) return;
								const local = picked.split('@')[0] ?? picked;
								void panel.propose(proposal(m.my_account_default_title({ address: picked }), 'put', '/api/me/default-mailbox', { body: { local } }));
							}}
						>
							<label class="flex grow basis-48 flex-col gap-1 text-sm">
								{m.my_account_default_mailbox_choose()}
								<select class={input} value={picked} onchange={(e) => (chosen = e.currentTarget.value)}>
									{#each person.mailboxes as box (box.address)}<option value={box.address}>{box.address}</option>{/each}
								</select>
							</label>
							<button type="submit" class={button} disabled={picked === current}>{m.my_account_make_default()}</button>
						</form>
						<p class="mt-1 text-xs text-muted-text">{m.my_account_default_mailbox_explanation()}</p>
					{/if}
				{/if}
			</Card>

			{#if person.account !== null}
				<Card title={m.my_account_identity()}>
					<Loaded resource={identity}>
						{#snippet children(i)}
							{#if i.link === 'linked'}
								{@const names = draft ?? namesOf(i)}
								<p class="mb-3 {muted}">{m.my_account_identity_explanation()}</p>
								<form
									class="flex flex-col gap-2"
									onsubmit={(e) => {
										e.preventDefault();
										void panel.propose(proposal(m.my_account_names_title(), 'put', '/api/me/identity', { body: names }));
									}}
								>
									<div class="flex flex-wrap gap-2">
										<label class="flex grow basis-40 flex-col gap-1 text-sm">
											{m.my_account_first_name()}
											<input class={input} value={names.first_name} maxlength={limits.NamesRequest.first_name.maxLength} autocomplete="given-name" oninput={(e) => (draft = { ...names, first_name: e.currentTarget.value })} />
										</label>
										<label class="flex grow basis-40 flex-col gap-1 text-sm">
											{m.my_account_last_name()}
											<input class={input} value={names.last_name} maxlength={limits.NamesRequest.last_name.maxLength} autocomplete="family-name" oninput={(e) => (draft = { ...names, last_name: e.currentTarget.value })} />
										</label>
									</div>
									<label class="flex flex-col gap-1 text-sm">
										{m.my_account_display_name()}
										<input class={input} value={names.display_name} required maxlength={limits.NamesRequest.display_name.maxLength} autocomplete="nickname" oninput={(e) => (draft = { ...names, display_name: e.currentTarget.value })} />
									</label>
									{#if i.email !== null}<p class="text-xs text-muted-text">{m.my_account_email({ address: i.email })}</p>{/if}
									{#if may('/api/me/identity', 'PUT')}
										<button type="submit" class={[primary, 'self-start']} disabled={names.display_name.trim() === ''}>{m.my_account_save_names()}</button>
									{/if}
								</form>
							{:else}
								<p class={muted}>{unlinked[i.link]()}</p>
							{/if}
							{#if i.passkeys_url !== null}
								<div class="mt-4 border-t border-border pt-3">
									<p class="mb-2 {muted}">{m.my_account_passkeys_explanation()}</p>
									<a class={button} href={i.passkeys_url} target="_blank" rel="noopener noreferrer">{m.my_account_passkeys()}</a>
								</div>
							{/if}
						{/snippet}
					</Loaded>
				</Card>

				<Card title={m.my_account_sessions()}>
					<p class="mb-2 {muted}">{m.my_account_sessions_explanation()}</p>
					<Loaded resource={sessions} empty={m.my_account_no_session()}>
						{#snippet children(list)}
							<ul>
								{#each list as s (s.reference)}
									<Row>
										<p class="text-sm">{device(s)} {#if s.current}<span class="text-muted-text">· {m.my_account_this_session()}</span>{/if}</p>
										<p class="text-xs text-muted-text">{m.my_account_session_seen({ age: duration(s.seen_s), left: duration(s.expires_in_s) })}</p>
										{#snippet aside()}
											{#if !s.current && may('/api/me/sessions/{reference}', 'DELETE')}
												<button type="button" class={button} onclick={() => panel.propose(proposal(m.my_account_sign_out_device_title({ device: device(s) }), 'delete', '/api/me/sessions/{reference}', { path: { reference: s.reference } }))}>{m.my_account_sign_out_device()}</button>
											{/if}
										{/snippet}
									</Row>
								{/each}
							</ul>
							{#if list.some((s) => s.current) && list.length > 1 && may('/api/me/sessions', 'DELETE')}
								<button type="button" class={[button, 'mt-3']} onclick={() => panel.propose(proposal(m.my_account_sign_out_elsewhere(), 'delete', '/api/me/sessions'))}>{m.my_account_sign_out_elsewhere()}</button>
							{/if}
						{/snippet}
					</Loaded>
				</Card>
			{/if}

			<Card title={m.my_account_what_you_can_do()}>
				<dl class="grid grid-cols-[1fr_auto] gap-x-4 gap-y-1.5 text-sm">
					{#each rights as [right, label] (right)}
						<dt>{label()}</dt>
						<dd class={person.can[right] ? 'text-ok' : 'text-muted-text'}>{person.can[right] ? m.my_account_yes() : m.my_account_no()}</dd>
					{/each}
				</dl>
			</Card>
		</div>
	{/snippet}
</Loaded>
