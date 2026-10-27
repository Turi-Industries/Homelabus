<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Row from '#lib/ui/Row.svelte';

	const tasks = read('/api/tasks');
	let failedOnly = $state(false);
</script>

<Card title={m.page_activity_tasks()}>
	{#snippet action()}
		<label class="flex items-center gap-2 text-sm"><input type="checkbox" bind:checked={failedOnly} />{m.tasks_failed_only()}</label>
	{/snippet}
	<Loaded resource={tasks} empty={m.widget_tasks_none()}>
		{#snippet children(list)}
			<ul>
				{#each list.filter((t) => !failedOnly || t.failed) as t (t.id)}
					<Row href="/apps/{t.service}">
						<p class="text-sm font-medium">{t.service}{t.slot === null ? '' : `.${t.slot}`}</p>
						<p class="text-xs text-muted-text">
							{m.tasks_wanted({ desired: t.desired_state, state: t.state })}
							{#if t.node !== null}· {m.tasks_on_node({ node: t.node })}{/if}
						</p>
						{#if t.explanation}<p class={['text-sm', t.failed ? 'text-critical' : 'text-muted-text']}>{t.explanation}</p>{/if}
					</Row>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
