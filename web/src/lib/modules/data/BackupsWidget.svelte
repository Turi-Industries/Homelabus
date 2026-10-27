<script lang="ts">
	import { when } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { tone } from '#lib/words.ts';

	const runs = read('/api/backups');
</script>

<Card fill title={m.widget_backups()} href="/backups/runs">
	<Loaded resource={runs} empty={m.widget_backups_none()}>
		{#snippet children(list)}
			<ul class="space-y-1.5">
				{#each list.slice(0, 30) as run (run.id)}
					<li class="flex flex-wrap items-baseline gap-x-2 text-sm">
						<span aria-hidden="true" class={['size-2 shrink-0 self-center rounded-full', run.succeeded ? tone.ok.bg : tone.critical.bg]}></span>
						<a href="/apps/{run.app}/backups" class="min-w-0 grow basis-24 truncate font-medium hover:underline">{run.app}</a>
						{#if run.destination}<span class="text-xs text-muted-text">{m.widget_backup_to({ destination: run.destination })}</span>{/if}
						<span class="text-xs text-muted-text">{when(run.when)}</span>
						<span class="sr-only">{run.succeeded ? m.widget_backup_done() : m.widget_backup_failed()}</span>
					</li>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
