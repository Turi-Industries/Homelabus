<script lang="ts">
	import { gap } from '#lib/drift.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { muted } from '#lib/ui/styles.ts';

	const drift = read('/api/drift');
</script>

<Loaded resource={drift} empty={m.drift_no_gap()}>
	{#snippet children(list)}
		{@const corrected = list.filter((d) => d.corrigible)}
		{@const left = list.filter((d) => !d.corrigible)}
		<div class="flex flex-col gap-4">
			{#if corrected.length > 0}
				<Card title={m.drift_will_be_corrected()}>
					<p class="mb-2 {muted}">{m.drift_correctable_explanation()}</p>
					<ul>
						{#each corrected as d (gap(d))}
							<Row><p class="text-sm">{d.description}</p>{#snippet aside()}<Mark attention={d.attention} />{/snippet}</Row>
						{/each}
					</ul>
				</Card>
			{/if}
			{#if left.length > 0}
				<Card title={m.drift_left_as_is_deliberately()}>
					<p class="mb-2 {muted}">{m.drift_refusal_explanation()}</p>
					<ul>
						{#each left as d (gap(d))}
							<Row>
								<p class="text-sm font-medium">{d.description}</p>
								{#if d.refusal}<p class="text-sm text-muted-text">{d.refusal}</p>{/if}
								{#snippet aside()}<Mark attention={d.attention} />{/snippet}
							</Row>
						{/each}
					</ul>
				</Card>
			{/if}
		</div>
	{/snippet}
</Loaded>
