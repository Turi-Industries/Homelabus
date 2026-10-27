<script lang="ts">
	import { number } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';

	const accounts = read('/api/accounts');
</script>

<Card fill title={m.widget_accounts()} href="/accounts">
	<Loaded resource={accounts}>
		{#snippet children(list)}
			{@const figures = [
				[number(list.length), m.widget_accounts_count()],
				[number(list.reduce((n, a) => n + a.mailboxes.length, 0)), m.widget_mailboxes_count()],
				[number(list.reduce((n, a) => n + a.active_aliases, 0)), m.widget_aliases_count()],
				[number(list.reduce((n, a) => n + a.sessions, 0)), m.widget_sessions_count()]
			]}
			<ul class="flex h-full flex-wrap content-stretch gap-2">
				{#each figures as [value, caption] (caption)}
					<li class="flex min-w-0 grow basis-24">
						<a href="/accounts" class="flex min-w-0 grow flex-col justify-center rounded-md bg-raised-surface px-3 py-1.5 hover:ring-1 hover:ring-border">
							<span class="text-xl font-semibold tabular-nums">{value}</span>
							<span class="truncate text-xs text-muted-text">{caption}</span>
						</a>
					</li>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
