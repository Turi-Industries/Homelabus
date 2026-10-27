<script lang="ts">
	import ExternalLink from '@lucide/svelte/icons/external-link';
	import { when } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import { muted } from '#lib/ui/styles.ts';

	const portal = read('/api/portal');
</script>

<Loaded resource={portal}>
	{#snippet children(p)}
		<div class="flex flex-col gap-6">
			{#if p.announcements.length > 0}
				<Card title={m.portal_announcements()}>
					<ul class="space-y-4">
						{#each p.announcements as a (a.id)}
							<li>
								<div class="flex flex-wrap items-center justify-between gap-2"><p class="font-medium">{a.title}</p><Mark attention={a.attention} /></div>
								<p class="text-sm whitespace-pre-line">{a.body}</p>
								{#each a.follow_ups as f, i (i)}
									<p class="mt-1 border-l-2 border-border pl-3 text-sm">{f.body} <span class="text-xs text-muted-text">— {m.portal_follow_up_at({ at: when(f.at), author: f.author })}</span></p>
								{/each}
							</li>
						{/each}
					</ul>
				</Card>
			{/if}

			<section>
				<h2 class="mb-1 text-base font-semibold">{m.portal_your_applications()}</h2>
				<p class="mb-3 {muted}">{m.portal_access_explanation()}</p>
				{#if p.apps.length === 0}<p class={muted}>{m.portal_no_exposed_application()}</p>{/if}
				<ul class="grid grid-cols-[repeat(auto-fill,minmax(14rem,1fr))] gap-3">
					{#each p.apps as app (app.name)}
						{@const name = app.name}
						<li>
							{#if app.available && app.domain}
								<a href="https://{app.domain}" target="_blank" rel="noreferrer" class="flex items-center gap-3 rounded-xl border border-border bg-surface p-3 hover:bg-raised-surface">
									<img src="/api/catalog/{name}/icon" alt="" class="size-10 rounded-lg bg-raised-surface" loading="lazy" onerror={(e) => ((e.currentTarget as HTMLImageElement).style.visibility = 'hidden')} />
									<span class="min-w-0 flex-1"><span class="block truncate font-medium">{app.display_name}</span><span class="block truncate text-xs text-muted-text">{app.domain}</span></span>
									<ExternalLink class="size-4 text-muted-text" />
								</a>
							{:else}
								<!-- 🔴 A link to a stopped app leads to an error read as a permissions problem. -->
								<div class="flex items-center gap-3 rounded-xl border border-border p-3 opacity-70">
									<img src="/api/catalog/{name}/icon" alt="" class="size-10 rounded-lg bg-raised-surface grayscale" loading="lazy" onerror={(e) => ((e.currentTarget as HTMLImageElement).style.visibility = 'hidden')} />
									<span class="min-w-0 flex-1"><span class="block truncate font-medium">{app.display_name}</span><span class="block truncate text-xs text-attention">{m.portal_stopped_domain({ domain: app.domain ?? app.name })}</span></span>
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			</section>

			{#if p.mailboxes.length > 0}
				<Card title={m.portal_your_addresses()} href="/me/mailbox">
					<ul class="text-sm">
						{#each p.mailboxes as box (box.address)}<li>{m.portal_address_with_default({ is_default: box.default ? '1' : '0', address: box.address })}</li>{/each}
					</ul>
				</Card>
			{/if}
		</div>
	{/snippet}
</Loaded>
