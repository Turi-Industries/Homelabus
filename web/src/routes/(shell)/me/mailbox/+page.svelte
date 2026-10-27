<script lang="ts">
	import { limits } from '#lib/api/limits.ts';
	import { panel, proposal } from '#lib/action.svelte.ts';
	import { api, type Schemas } from '#lib/api/client.ts';
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read, refusal } from '#lib/resource.svelte.ts';
	import { me, may } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { button, danger, input, muted, primary } from '#lib/ui/styles.ts';

	const who = me();
	const aliases = read('/api/me/aliases');
	let local = $state('');
	let hint = $state('');
	let note = $state<{ ok: boolean; text: string } | undefined>();

	function lifecycle(l: Schemas['AliasLifecycle']): string {
		switch (l.kind) {
			case 'permanent':
				return m.me_alias_permanent();
			case 'valid':
				return m.me_alias_valid({ left: duration(l.expires_in_s) });
			case 'expired':
				return m.me_alias_expired();
			case 'expired_but_active':
				return m.me_alias_expired_active({ since: duration(l.since_s) });
			case 'unknown':
				return m.me_alias_unknown();
		}
		const _: never = l;
		return _;
	}

	// Creating is not idempotent: a second press while the first is in flight is a
	// second alias.
	let creating = $state(false);

	async function createAlias() {
		if (creating) return;
		creating = true;
		try {
			const { data, error, response } = await api.POST('/api/v1/aliases', {
				body: { description: hint.trim(), domain: null }
			});
			note = data ? { ok: true, text: m.me_alias_created({ address: data.data.email }) } : { ok: false, text: m.me_alias_failed({ error: refusal(error, response) }) };
			// Kept when refused, so it can be sent again as it was.
			if (data) hint = '';
		} catch (e) {
			note = { ok: false, text: m.me_alias_failed({ error: e instanceof Error ? e.message : String(e) }) };
		} finally {
			creating = false;
		}
		await aliases.refresh();
	}
</script>

<Loaded resource={who}>
	{#snippet children(person)}
		<div class="grid gap-4 lg:grid-cols-[2fr_1fr]">
			<Card title={m.my_mailbox_my_aliases()}>
				<Loaded resource={aliases} empty={m.my_mailbox_no_alias_yet()}>
					{#snippet children(list)}
						{@const stillOpen = list.filter((a) => a.lifecycle.kind === 'expired_but_active').length}
						{#if stillOpen > 0}
							<p class="mb-3 text-sm text-critical">{m.my_mailbox_expired_still_receiving({ count: stillOpen })} <span class="text-muted-text">{m.my_mailbox_purge_explanation()}</span></p>
						{/if}
						<ul>
							{#each list as a (a.address)}
								{@const localPart = a.address.split('@')[0] ?? a.address}
								<Row>
									<p class="font-mono text-sm">{a.address}</p>
									<p class="text-xs text-muted-text">{a.hint ?? ''} {a.hint ? '·' : ''} {lifecycle(a.lifecycle)} · {m.my_mailbox_delivers_to({ address: a.mailbox })}</p>
									{#snippet aside()}
										<Mark attention={a.attention} />
										{#if a.active && may('/api/v1/my-aliases/{local}/disable', 'POST')}
											<button type="button" class={button} onclick={() => panel.propose(proposal(m.me_disable_title({ address: a.address }), 'post', '/api/v1/my-aliases/{local}/disable', { path: { local: localPart } }))}>{m.my_mailbox_disable()}</button>
										{/if}
										{#if may('/api/v1/my-aliases/{local}/purge', 'POST')}
											<button type="button" class={danger} onclick={() => panel.propose(proposal(m.me_purge_title({ address: a.address }), 'post', '/api/v1/my-aliases/{local}/purge', { path: { local: localPart } }))}>{m.my_mailbox_purge()}</button>
										{/if}
									{/snippet}
								</Row>
							{/each}
						</ul>
					{/snippet}
				</Loaded>
			</Card>

			<div class="flex flex-col gap-4">
				{#if person.mailboxes.length === 0}
					<Card title={m.my_mailbox_create_my_mailbox()}>
						<p class="mb-3 {muted}">{m.my_mailbox_no_mailbox_on_account()}</p>
						<form class="flex flex-col gap-2" onsubmit={(e) => (e.preventDefault(), void panel.immediate(m.me_create_mailbox_title({ local }), () => api.POST('/api/me/mailbox', { body: { local: local.trim() } })))}>
							<label class="flex flex-col gap-1 text-sm">{m.my_mailbox_local_part()}<input bind:value={local} maxlength={limits.CreateMailboxRequest.local.maxLength} autocapitalize="none" spellcheck="false" class={input} /></label>
							<p class="text-xs text-muted-text">{m.my_mailbox_local_part_explanation()}</p>
							<button type="submit" class={[primary, 'self-start']} disabled={local.trim() === ''}>{m.my_mailbox_create()}</button>
						</form>
					</Card>
				{:else if person.account !== null}
					<Card title={m.my_mailbox_create_an_alias()}>
						<p class="mb-3 {muted}">{m.my_mailbox_hint_explanation()}</p>
						<form class="flex flex-col gap-2" onsubmit={(e) => (e.preventDefault(), void createAlias())}>
							<label class="flex flex-col gap-1 text-sm">{m.me_hint_label()}<input bind:value={hint} maxlength={limits.CreationRequest.description.maxLength} autocapitalize="none" class={input} /></label>
							<button type="submit" class={[primary, 'self-start']} disabled={creating || hint.trim() === ''}>{m.my_mailbox_create()}</button>
							{#if note}<p role="status" class={['text-sm', note.ok ? 'text-ok' : 'text-critical']}>{note.text}</p>{/if}
						</form>
					</Card>
				{/if}
			</div>
		</div>
	{/snippet}
</Loaded>
