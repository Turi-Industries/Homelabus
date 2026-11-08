<script lang="ts">
	import { proposal, panel } from '#lib/action.svelte.ts';
	import { when } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { button, muted } from '#lib/ui/styles.ts';
	import { moves, refused, who, why, type WaitingUpdate } from '#lib/updates.ts';

	const updates = read('/api/updates');

	function approve(u: WaitingUpdate) {
		panel.propose(
			proposal(m.updates_approve_title({ app: u.app }), 'post', '/api/apps/{name}/update/approve', {
				path: { name: u.app }
			})
		);
	}
</script>

<div class="flex flex-col gap-4">
	<Card title={m.updates_title()}>
		<p class="mb-3 {muted}">{m.updates_intro()}</p>
		<Loaded resource={updates} empty={m.updates_none()}>
			{#snippet children(list)}
				<ul>
					{#each list as u (u.app)}
						<Row>
							<p class="font-medium">
								<a href="/apps/{u.app}" class="hover:underline">{u.app}</a>
								<span class="font-normal text-muted-text">· {moves(u)}</span>
							</p>
							<p class="text-sm">{who(u)}{#if u.why !== null}<span class="text-muted-text"> — {why(u.why)}</span>{/if}</p>
							{#if u.why?.kind === 'notes_unreadable'}
								<p class="text-sm break-words text-muted-text">{u.why.error}</p>
							{/if}
							{#if u.notes !== null && u.notes.length > 0}
								<p class="text-sm">
									{m.updates_notes()}
									{#each u.notes as n, i (n.tag)}{#if i > 0}, {/if}<a href={n.url} target="_blank" rel="noreferrer" class="underline">{n.tag}</a>{/each}
								</p>
							{/if}
							{#if u.refused !== null && u.needs === 'look'}
								{@const r = refused(u.refused)}
								<p class="text-sm text-critical">{r.said}</p>
								{#if r.detail !== null}
									<pre class="mt-1 text-xs break-words whitespace-pre-wrap text-muted-text">{r.detail}</pre>
								{/if}
							{/if}
							{#if u.approved && u.approved_at !== null}
								<p class="text-sm text-muted-text">
									{m.updates_approved({ by: u.approved_by ?? '', at: when(u.approved_at) })}
								</p>
							{/if}
							{#snippet aside()}
								{#if u.needs === 'look'}
									<Mark attention="critical" label={m.updates_mark_refused()} />
								{:else if u.needs !== null}
									<Mark attention="notice" label={m.updates_mark_waiting()} />
								{/if}
								{#if (u.needs === 'approval' || u.needs === 'look') && may('/api/apps/{name}/update/approve', 'POST')}
									<button type="button" class={button} onclick={() => approve(u)}
										>{u.needs === 'look' ? m.updates_approve_again() : m.updates_approve()}</button
									>
								{/if}
							{/snippet}
						</Row>
					{/each}
				</ul>
			{/snippet}
		</Loaded>
	</Card>
</div>
