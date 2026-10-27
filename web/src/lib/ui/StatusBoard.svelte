<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import { when } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import Card from './Card.svelte';
	import Mark from './Mark.svelte';
	import { service, status, tone } from '#lib/words.ts';

	/**
	 * The status page's body, shared by the signed-in page and the public one: what
	 * works, what does not, and the incidents being followed.
	 */
	let { page }: { page: Schemas['StatusPage'] } = $props();

	const incidents = $derived(page.incidents.filter((a) => a.level === 'incident'));
	// An announced maintenance is not an outage: it gets its own heading.
	const maintenance = $derived(page.incidents.filter((a) => a.level === 'maintenance'));
</script>

<div class="flex flex-col gap-4">
	<div class={['rounded-xl border p-5', tone[page.attention].border]}>
		<p class={['text-lg font-semibold', tone[page.attention].text]}>{status(page.verdict)}</p>
		{#if page.public}<p class="mt-1 text-sm text-attention">{m.status_public_warning()}</p>{/if}
	</div>

	{#each [[m.status_ongoing_incidents(), incidents], [m.status_scheduled_maintenance(), maintenance]] as const as [title, list] (title)}
		{#if list.length > 0}
			<Card {title}>
				<ul class="space-y-4">
					{#each list as a (a.id)}
						<li>
							<p class="font-medium">{a.title}</p>
							<p class="text-sm whitespace-pre-line">{a.body}</p>
							<ol class="mt-2 space-y-1 border-l-2 border-border pl-3">
								{#each a.follow_ups as f, i (i)}
									<li class="text-sm">{f.body} <span class="text-xs text-muted-text">— {m.portal_follow_up_at({ at: when(f.at), author: f.author })}</span></li>
								{:else}
									<li class="text-sm text-muted-text">{m.portal_no_updates_since_published()}</li>
								{/each}
							</ol>
						</li>
					{/each}
				</ul>
			</Card>
		{/if}
	{/each}

	<!-- With nothing exposed the verdict already says so; an empty card would say it twice. -->
	{#if page.services.length > 0}
	<Card title={m.status_services()}>
		<ul class="space-y-4">
			{#each page.services as s (s.name)}
				<li>
					<div class="flex flex-wrap items-center justify-between gap-2">
						<span class="font-medium">{s.name} {#if s.domain}<span class="text-xs font-normal text-muted-text">{s.domain}</span>{/if}</span>
						<Mark attention={s.attention} label={service(s.state)} />
					</div>
					<!-- One bar a day. A day with no sample is drawn apart: no data is not "up". -->
					<div class="mt-2 flex h-6 gap-px" aria-label={m.status_history()} role="img">
						{#each s.uptime as day (day.day)}
							<span
								class={['flex-1 rounded-sm', day.attention === null ? 'bg-raised-surface' : tone[day.attention].bg]}
								title={m.me_uptime_day({ day: day.day, state: day.state === null ? m.me_uptime_no_sample() : service(day.state) })}
							></span>
						{/each}
					</div>
				</li>
			{/each}
		</ul>
	</Card>
	{/if}
</div>
