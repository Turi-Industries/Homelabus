<script lang="ts">
	import { panel, proposal } from '#lib/action.svelte.ts';
	import { limits } from '#lib/api/limits.ts';
	import { when } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may, me } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { button, code, input, muted, primary } from '#lib/ui/styles.ts';

	const who = me();
	const devices = read('/api/me/devices');

	let name = $state('');
	let chosen = $state<string | undefined>();
</script>

<Loaded resource={who}>
	{#snippet children(person)}
		{#if person.account === null}
			<Card title={m.nav_service_token()}>
				<p class={muted}>{m.my_account_service_token_explanation()}</p>
				<code class="mt-2 block {code}">{m.my_account_service_token_command()}</code>
			</Card>
		{:else}
			<div class="grid gap-4 lg:grid-cols-2">
				<Card title={m.page_me_devices()}>
					<p class="mb-3 {muted}">{m.my_devices_explanation()}</p>
					{#if may('/api/me/devices', 'POST')}
						{@const fallback = person.mailboxes.find((b) => b.default)?.address}
						{@const picked = chosen ?? fallback}
						<form
							class="flex flex-col gap-2"
							onsubmit={(e) => {
								e.preventDefault();
								const device = name.trim();
								// The default mailbox is the server's to find: sent only when another is picked.
								const mailbox = picked !== undefined && picked !== fallback ? (picked.split('@')[0] ?? null) : null;
								void panel.propose(proposal(m.my_devices_add_title({ name: device }), 'post', '/api/me/devices', { body: { name: device, mailbox } }));
							}}
						>
							<label class="flex flex-col gap-1 text-sm">
								{m.my_devices_name()}
								<input class={input} bind:value={name} required maxlength={limits.DeviceRequest.name.maxLength} placeholder={m.my_devices_name_hint()} autocomplete="off" />
							</label>
							{#if person.mailboxes.length > 1}
								<label class="flex flex-col gap-1 text-sm">
									{m.my_devices_mailbox()}
									<select class={input} value={picked} onchange={(e) => (chosen = e.currentTarget.value)}>
										{#each person.mailboxes as box (box.address)}<option value={box.address}>{box.address}</option>{/each}
									</select>
								</label>
							{/if}
							<button type="submit" class={[primary, 'self-start']} disabled={name.trim() === ''}>{m.my_devices_add()}</button>
						</form>
					{/if}
				</Card>

				<Card title={m.my_devices_list()}>
					<Loaded resource={devices}>
						{#snippet children(mine)}
							{#if mine.unreadable !== null}
								<p role="alert" class="text-sm text-attention">{m.my_devices_unreadable({ error: mine.unreadable })}</p>
							{:else if mine.devices.length === 0}
								<p class={muted}>{m.my_devices_none()}</p>
							{:else}
								<ul>
									{#each mine.devices as d (`${d.mailbox}/${d.id}`)}
										<Row>
											<p class="text-sm">{d.name}</p>
											<p class="text-xs text-muted-text">
												{d.created_at === null ? d.mailbox : m.my_devices_made({ mailbox: d.mailbox, date: when(d.created_at) })}
											</p>
											{#snippet aside()}
												{#if may('/api/me/devices/{mailbox}/{id}', 'DELETE')}
													<button
														type="button"
														class={button}
														onclick={() =>
															panel.propose(
																proposal(m.my_devices_revoke_title({ name: d.name }), 'delete', '/api/me/devices/{mailbox}/{id}', {
																	path: { mailbox: d.mailbox.split('@')[0] ?? d.mailbox, id: d.id }
																})
															)}>{m.my_devices_revoke()}</button
													>
												{/if}
											{/snippet}
										</Row>
									{/each}
								</ul>
							{/if}
						{/snippet}
					</Loaded>
				</Card>
			</div>
		{/if}
	{/snippet}
</Loaded>
