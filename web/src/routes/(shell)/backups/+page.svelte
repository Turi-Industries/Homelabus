<script lang="ts">
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import { code, muted } from '#lib/ui/styles.ts';
	import { coverage, tone } from '#lib/words.ts';

	const apps = read('/api/coverage');
	const rank = { critical: 0, notice: 1, ok: 2 };
</script>

<Loaded resource={apps} empty={m.backups_no_application_installed()}>
	{#snippet children(list)}
		{@const none = list.filter((c) => c.up_to_date_copies === 0).length}
		{@const single = list.filter((c) => c.up_to_date_copies === 1).length}
		{@const destinations = [...new Set(list.flatMap((c) => c.per_destination.map(([d]) => d)))]}
		<div class="flex flex-col gap-4">
			<Card>
				<p class="font-medium">
					{#if none > 0}<span class="text-critical">{m.backups_no_up_to_date_copy({ count: none })}</span>{/if}
					{#if single > 0}<span class="text-attention">{m.backups_single_copy({ count: single })}</span>{/if}
					{#if none === 0 && single === 0}{m.backups_at_least_two_copies()}{/if}
				</p>
				<p class="mt-1 {muted}">{m.backups_protection_explanation()}</p>
				{#if destinations.length === 0}<code class="mt-2 block {code}">{m.backups_dest_add_command()}</code>{/if}
			</Card>
			<Card title={m.backups_coverage_per_application()}>
				<div class="overflow-x-auto">
					<table class="w-full text-sm">
						<thead>
							<tr class="text-left text-xs text-muted-text">
								<th class="py-2 pr-4 font-medium">{m.nav_apps()}</th>
								{#each destinations as d (d)}<th class="py-2 pr-4 font-medium">{d}</th>{/each}
							</tr>
						</thead>
						<tbody>
							{#each [...list].sort((a, b) => rank[a.attention] - rank[b.attention]) as c (c.app)}
								{@const ages = new Map(c.per_destination)}
								<tr class="border-t border-border">
									<td class="min-w-36 py-2 pr-4">
										<!-- The verdict sits with the name: in a last column, a phone scrolled it
										     out of sight — the one cell the table is read for. -->
										<span class="flex flex-wrap items-center gap-x-2 gap-y-1">
											<a href="/apps/{c.app}/backups" class="font-medium hover:underline">{c.app}</a>
											<Mark attention={c.attention} />
										</span>
										<span class="block text-xs text-muted-text">{coverage(c.coverage)}</span>
									</td>
									{#each destinations as d (d)}
										{@const age = ages.get(d)}
										<td class={['py-2 pr-4 tabular-nums', age === null || age === undefined ? tone.critical.text : '']}>
											{age === null || age === undefined ? m.backups_never() : duration(age)}
										</td>
									{/each}
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</Card>
		</div>
	{/snippet}
</Loaded>
