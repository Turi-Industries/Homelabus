<script lang="ts">
	import { proposal, panel } from '#lib/action.svelte.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { button, muted } from '#lib/ui/styles.ts';

	const todo = read('/api/todo');
</script>

<div class="flex flex-col gap-4">
	<Card title={m.todo_title()}>
		<p class="mb-3 {muted}">{m.todo_ack_is_an_attestation()}</p>
		<Loaded resource={todo} empty={m.todo_no_manual_action_pending()}>
			{#snippet children(list)}
				<ul>
					{#each list as item (`${item.app}/${item.id}`)}
						<Row>
							<p class="font-medium">{item.title}</p>
							<p class="text-sm text-muted-text">
								<a href="/apps/{item.app}" class="hover:underline">{item.app}</a>
								{#if item.blocking}<span class="text-critical">· {m.todo_blocking()}</span>{/if}
							</p>
							{#snippet aside()}
								{#if may('/api/todo/{app}/{id}', 'POST')}
									<button
										type="button"
										class={button}
										onclick={() => panel.propose(proposal(m.todo_attest_title({ title: item.title }), 'post', '/api/todo/{app}/{id}', { path: { app: item.app, id: item.id } }))}
										>{m.todo_attest()}</button
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
