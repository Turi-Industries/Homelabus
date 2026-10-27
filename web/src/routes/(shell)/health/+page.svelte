<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { code, muted } from '#lib/ui/styles.ts';
	import { healthFinding, healthTopic } from '#lib/words.ts';

	const health = read('/api/health');
	const rank = { critical: 0, notice: 1, ok: 2 };
</script>

<Card title={m.todo_installation_health()}>
	<p class="mb-3 {muted}">{m.todo_health_explanation()}</p>
	<Loaded resource={health}>
		{#snippet children(checks)}
			<ul>
				{#each [...checks].sort((a, b) => rank[a.attention] - rank[b.attention]) as c (c.finding.kind)}
					<Row>
						<p class="font-medium">{healthTopic(c.finding)}</p>
						<p class="text-sm text-muted-text">{healthFinding(c.finding)}</p>
						{#if c.remedy}<code class="mt-1 inline-block {code}">{c.remedy}</code>{/if}
						{#snippet aside()}<Mark attention={c.attention} />{/snippet}
					</Row>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
