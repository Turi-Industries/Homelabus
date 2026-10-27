<script lang="ts">
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { muted } from '#lib/ui/styles.ts';

	const plans = read('/api/plans');
</script>

<Card title={m.plans_title()}>
	<p class="mb-3 {muted}">{m.plans_replay_explanation()}</p>
	<Loaded resource={plans} empty={m.plans_no_prepared_plan()}>
		{#snippet children(list)}
			<ul>
				{#each list as plan (plan.name)}
					<Row>
						<p class="font-medium">{plan.name}</p>
						<p class="text-sm">{plan.summary}</p>
						<p class="font-mono text-xs text-muted-text">{plan.method} {plan.path}</p>
						{#snippet aside()}
							<span class="text-xs text-muted-text">{m.plans_by({ author: plan.created_by, age: duration(plan.age_s) })}</span>
							<Mark attention={plan.attention} />
						{/snippet}
					</Row>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
