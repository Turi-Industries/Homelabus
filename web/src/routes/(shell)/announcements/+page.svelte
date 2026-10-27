<script lang="ts">
	import { limits } from '#lib/api/limits.ts';
	import { proposal, panel } from '#lib/action.svelte.ts';
	import type { Schemas } from '#lib/api/client.ts';
	import { when } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import { button, danger, input, muted, primary } from '#lib/ui/styles.ts';

	type Level = Schemas['AnnouncementLevel'];
	const announcements = read('/api/announcements');
	const levels: Record<Level, () => string> = {
		info: m.announcements_level_information,
		maintenance: m.announcements_level_maintenance,
		warning: m.announcements_level_warning,
		incident: m.announcements_level_incident
	};
	const audiences = {
		'': m.announcements_audience_everyone,
		viewer: m.announcements_audience_viewer_up,
		operator: m.announcements_audience_operations,
		admin: m.announcements_audience_admins
	};

	let title = $state('');
	let body = $state('');
	let level = $state<Level>('info');
	let audience = $state<keyof typeof audiences>('');
	let pinned = $state(false);
	let updates = $state<Record<number, string>>({});
</script>

<div class="grid gap-4 lg:grid-cols-[2fr_1fr]">
	<Card title={m.announcements_published()}>
		<Loaded resource={announcements} empty={m.announcements_no_announcement_published()}>
			{#snippet children(list)}
				<ul class="space-y-5">
					{#each list as a (a.id)}
						<li class="border-b border-border pb-4 last:border-b-0">
							<div class="flex flex-wrap items-center justify-between gap-2">
								<p class="font-medium">{a.title} {#if a.pinned}<span class="text-xs text-muted-text">· {m.announcements_pinned()}</span>{/if}</p>
								<Mark attention={a.attention} label={levels[a.level]()} />
							</div>
							<p class="text-xs text-muted-text">{m.announcements_published_by_at({ at: when(a.published_at), author: a.author })}</p>
							<p class="mt-1 text-sm whitespace-pre-line">{a.body}</p>
							{#if a.follow_ups.length > 0}
								<ol class="mt-2 space-y-1 border-l-2 border-border pl-3">
									{#each a.follow_ups as f, i (i)}
										<li class="text-sm">{f.body} <span class="text-xs text-muted-text">— {m.portal_follow_up_at({ at: when(f.at), author: f.author })}</span></li>
									{/each}
								</ol>
							{/if}
							{#if a.open_incident}<p class="mt-2 text-xs text-attention">{m.announcements_to_close_incident()}</p>{/if}
							{#if may('/api/announcements/{id}/follow_ups', 'POST')}
								<form
									class="mt-3 flex flex-wrap gap-2"
									onsubmit={(e) => {
										e.preventDefault();
										const text = (updates[a.id] ?? '').trim();
										if (text === '') return;
										void panel.propose(proposal(m.people_follow_up_title({ title: a.title }), 'post', '/api/announcements/{id}/follow_ups', { path: { id: a.id }, body: { body: text } }));
									}}
								>
									<input bind:value={updates[a.id]} maxlength={limits.FollowUpRequest.body.maxLength} placeholder={m.announcements_update_hint()} class={[input, 'grow basis-48']} />
									<button type="submit" class={button}>{m.announcements_add_an_update()}</button>
									<button type="button" class={danger} onclick={() => panel.propose(proposal(m.people_remove_title({ title: a.title }), 'delete', '/api/announcements/{id}', { path: { id: a.id } }))}>{m.announcements_remove()}</button>
								</form>
							{/if}
						</li>
					{/each}
				</ul>
			{/snippet}
		</Loaded>
	</Card>

	<Card title={m.people_new_announcement()}>
		<form
			class="flex flex-col gap-3"
			onsubmit={(e) => {
				e.preventDefault();
				void panel.propose(
					proposal(m.people_publish_title({ title }), 'post', '/api/announcements', {
						body: { title: title.trim(), body: body.trim(), level, audience: audience === '' ? null : audience, pinned, duration_s: null }
					})
				);
			}}
		>
			<input bind:value={title} maxlength={limits.AnnouncementRequest.title.maxLength} placeholder={m.announcements_title_hint()} aria-label={m.announcements_title_hint()} class={input} />
			<textarea bind:value={body} rows="4" maxlength={limits.AnnouncementRequest.body.maxLength} placeholder={m.announcements_body_hint()} aria-label={m.announcements_body_hint()} class={input}></textarea>
			<label class="flex flex-col gap-1 text-sm">{m.announcements_level_label()}
				<select bind:value={level} class={input}>{#each Object.entries(levels) as [l, label] (l)}<option value={l}>{label()}</option>{/each}</select>
			</label>
			<label class="flex flex-col gap-1 text-sm">{m.announcements_audience_label()}
				<select bind:value={audience} class={input}>{#each Object.entries(audiences) as [a, label] (a)}<option value={a}>{label()}</option>{/each}</select>
			</label>
			<label class="flex items-center gap-2 text-sm"><input type="checkbox" bind:checked={pinned} />{m.announcements_pin()}</label>
			{#if level === 'incident'}
				<p class="text-sm text-attention">{m.announcements_incident_visible_to_everyone()} <span class="text-muted-text">{m.announcements_incident_visible_explanation()}</span></p>
			{:else if level === 'maintenance' && audience === ''}
				<p class="text-sm text-attention">{m.announcements_maintenance_reaches_portal()} <span class="text-muted-text">{m.announcements_maintenance_explanation()}</span></p>
			{/if}
			<button type="submit" class={primary} disabled={title.trim() === '' || body.trim() === ''}>{m.announcements_publish_ellipsis()}</button>
			{#if title.trim() === '' || body.trim() === ''}<p class={muted}>{m.announcements_title_and_body_needed()}</p>{/if}
		</form>
	</Card>
</div>
