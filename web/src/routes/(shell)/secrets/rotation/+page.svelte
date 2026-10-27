<script lang="ts">
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import { muted } from '#lib/ui/styles.ts';
	import { consequence, rotationStep } from '#lib/words.ts';

	const secrets = read('/api/secrets/rotation');
	const rank = { critical: 0, notice: 1, ok: 2 };
</script>

<div class="flex flex-col gap-4">
	<p class={muted}>{m.secrets_rotation_explanation()}</p>
	<Loaded resource={secrets} empty={m.secrets_no_secret_recorded()}>
		{#snippet children(list)}
			<div class="grid gap-4 lg:grid-cols-2">
				{#each [...list].sort((a, b) => rank[a.attention] - rank[b.attention] || b.age_s - a.age_s) as s (s.name)}
					<Card title={s.name}>
						{#snippet action()}<Mark attention={s.attention} />{/snippet}
						<p class="text-sm text-muted-text">
							{s.usage} · {s.never_rotated ? m.secrets_created_ago({ age: duration(s.age_s) }) : m.secrets_rotated_ago({ age: duration(s.age_s) })}
						</p>
						<p class="mt-2 text-sm">{consequence(s.consequence)}</p>
						{#if s.procedure.length === 0}
							<p class="mt-2 text-sm text-attention">{m.secrets_kind_not_recognised()}</p>
						{:else}
							<ol class="mt-2 list-decimal space-y-1 pl-5 text-sm">
								{#each s.procedure as step, i (i)}<li>{rotationStep[step]()}</li>{/each}
							</ol>
						{/if}
					</Card>
				{/each}
			</div>
		{/snippet}
	</Loaded>
</div>
