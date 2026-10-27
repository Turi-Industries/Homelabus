<script lang="ts">
	import { api } from '#lib/api/client.ts';
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read, refusal } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import { button, muted } from '#lib/ui/styles.ts';
	import { recovery as verdict } from '#lib/words.ts';

	const recovery = read('/api/recovery');
	let failure = $state<string | undefined>();

	// A declaration, reversible in one click: no preview, by the route's own choice.
	async function attest(id: string) {
		const { error, response } = await api.POST('/api/recovery/{id}', { params: { path: { id } } });
		failure = response.ok ? undefined : m.people_attest_failed({ error: refusal(error, response) });
		await recovery.refresh();
	}
</script>

<Loaded resource={recovery}>
	{#snippet children(r)}
		<div class="flex flex-col gap-4">
			<Card>
				<p class="font-medium">{verdict(r.verdict)}</p>
				<p class="mt-1 {muted}">{m.security_break_glass_explanation()}</p>
				{#if failure}<p role="alert" class="mt-2 text-sm text-critical">{failure}</p>{/if}
			</Card>
			<div class="grid gap-4 lg:grid-cols-2">
				{#each r.safeguards as s (s.id)}
					<Card title={s.title}>
						{#snippet action()}<Mark attention={s.attention} />{/snippet}
						<p class="text-sm">{s.why}</p>
						<p class="mt-2 {muted}">{s.comment}</p>
						<p class="mt-2 text-xs text-muted-text">
							{s.attested_ago_s === null
								? m.people_never_attested()
								: m.people_last_attested({ age: duration(s.attested_ago_s, s.resolution_day ? 'days' : 'seconds'), by: s.attested_by ?? '?' })}
						</p>
						<div class="mt-3">
							{#if s.verifiable}
								<p class="text-xs text-muted-text">{m.security_verified_by_homelabus()}</p>
							{:else if may('/api/recovery/{id}', 'POST')}
								<button type="button" class={button} onclick={() => attest(s.id)}>{m.security_i_have_checked_this_point()}</button>
							{/if}
						</div>
					</Card>
				{/each}
			</div>
		</div>
	{/snippet}
</Loaded>
