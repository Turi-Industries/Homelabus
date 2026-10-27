<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';

	const tasks = read('/api/tasks');
</script>

<!-- Each Swarm service and how many of its replicas run. -->
<Card fill title={m.widget_tasks()} href="/tasks">
	<Loaded resource={tasks} empty={m.widget_tasks_none()}>
		{#snippet children(list)}
			{@const services = [...Map.groupBy(list, (t) => t.service)].toSorted(([a], [b]) => a.localeCompare(b))}
			<ul class="space-y-1.5">
				{#each services as [name, replicas] (name)}
					{@const alive = replicas.filter((t) => t.alive).length}
					<li class="flex items-baseline gap-2 text-sm">
						<span class="min-w-0 grow truncate">{name}</span>
						<span class={['shrink-0 text-xs tabular-nums', alive === replicas.length ? 'text-muted-text' : 'text-attention']}>{m.widget_replicas({ alive, total: replicas.length })}</span>
					</li>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
