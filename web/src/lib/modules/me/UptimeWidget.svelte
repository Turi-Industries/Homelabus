<script lang="ts">
	import { day as dayOf } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { service, tone } from '#lib/words.ts';

	const page = read('/api/status');
</script>

<Card fill title={m.widget_uptime()} href="/me/status">
	<Loaded resource={page}>
		{#snippet children(s)}
			{#if s.services.length === 0}
				<p class="text-sm text-muted-text">{m.widget_services_none()}</p>
			{/if}
			<ul class="space-y-2">
				{#each s.services as svc (svc.name)}
					<li>
						<p class="flex justify-between gap-2 text-xs"><span class="truncate font-medium">{svc.name}</span><span class="text-muted-text">{service(svc.state)}</span></p>
						<!-- One bar a day. A day with no sample is drawn apart: no data is not "up". -->
						<div class="mt-1 flex h-3 gap-px" role="img" aria-label={m.status_history()}>
							{#each svc.uptime as day (day.day)}
								<span title="{dayOf(day.day)} — {day.state === null ? m.status_no_data() : service(day.state)}" class={['grow rounded-sm', day.attention === null ? 'bg-raised-surface' : tone[day.attention].bg]}></span>
							{/each}
						</div>
					</li>
				{/each}
			</ul>
			<!-- What the bars cover: a frieze with no dates is a pattern, not a history. -->
			{@const days = s.services[0]?.uptime ?? []}
			{#if days.length > 1}
				<p class="mt-1 flex justify-between text-xs text-muted-text"><span>{dayOf(days[0]?.day ?? '')}</span><span>{dayOf(days[days.length - 1]?.day ?? '')}</span></p>
			{/if}
		{/snippet}
	</Loaded>
</Card>
