<script lang="ts">
	import ExternalLink from '@lucide/svelte/icons/external-link';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { number } from '#lib/format.ts';
	import { histories, historyOf } from '#lib/home/history.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Sparkline from '#lib/ui/Sparkline.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { tone } from '#lib/words.ts';

	const apps = read('/api/apps');
	const all = $derived(histories());
	$effect(() => all.watch());
	const past = $derived(historyOf(all.data, 'apps_running'));
</script>

<!-- Every application and whether it runs: the dot is the server's attention, the word
     its own status, and a running one with an address opens from here. -->
<Card fill title={m.widget_apps()} href="/apps">
	<Loaded resource={apps} empty={m.apps_no_application_installed()}>
		{#snippet children(list)}
			{@const running = past?.lines[0]}
			{#if past !== undefined && running !== undefined && running.points.length > 1}
				<!-- How many ran over the period: a stop shows as a step down. -->
				<div class="mb-2">
					<Sparkline lines={[{ points: running.points, name: m.summary_apps() }]} from={past.from} to={past.now} step={past.step_s} max={list.length} format={(v) => number(v)} label={m.widget_apps_curve()} height={28} />
				</div>
			{/if}
			<ul class="space-y-1.5">
				{#each list.toSorted((a, b) => a.name.localeCompare(b.name)) as app (app.name)}
					<li class="flex items-center gap-2 text-sm">
						<span aria-hidden="true" class={['size-2 shrink-0 rounded-full', tone[app.attention].bg]}></span>
						<img src="/api/catalog/{app.name}/icon" alt="" class="size-4 shrink-0 rounded" loading="lazy" onerror={(e) => ((e.currentTarget as HTMLImageElement).style.visibility = 'hidden')} />
						<a href="/apps/{app.name}" class="min-w-0 grow truncate hover:underline">{app.name}</a>
						<span class="shrink-0 text-xs text-muted-text">{app.status}</span>
						{#if app.domain && app.status === 'running'}
							<a href="https://{app.domain}" target="_blank" rel="noreferrer" aria-label={m.widget_open({ app: app.name })} title={app.domain} class="shrink-0 rounded p-0.5 text-muted-text hover:text-accent">
								<ExternalLink aria-hidden="true" class="size-3.5" />
							</a>
						{/if}
					</li>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>
