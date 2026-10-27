<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import { limits } from '#lib/api/limits.ts';
	import { page } from '$app/state';
	import ExternalLink from '@lucide/svelte/icons/external-link';
	import { proposal, panel } from '#lib/action.svelte.ts';
	import { duration, when } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import { button, code, danger, input, muted } from '#lib/ui/styles.ts';
	import { coverage, need } from '#lib/words.ts';

	/**
	 * 🔴 The tabs that exist, as a union: the bar is this list, the body a `switch`
	 * ending on `never` — a tab offered and not written, or written and not offered,
	 * does not compile. An unknown slug falls back to the overview, so a link to a
	 * renamed tab still opens the right application.
	 */
	const tabs = ['overview', 'config', 'backups', 'history'] as const;
	type Tab = (typeof tabs)[number];
	const labels: Record<Tab, () => string> = {
		overview: m.app_tab_overview,
		config: m.app_tab_config,
		backups: m.app_tab_backups,
		history: m.app_tab_history
	};

	const name = $derived(page.params.name ?? '');
	const tab = $derived<Tab>(tabs.find((t) => t === page.params.tab) ?? 'overview');
	const detail = $derived(read('/api/apps/{name}/detail', { path: { name } }));
	const versions = $derived(read('/api/apps/{name}/versions', { path: { name } }));
	$effect(() => versions.watch());

	let replicas = $state<number | undefined>();
	const verdicts: Record<Schemas['AssertionVerdict'], () => string> = {
		holds: m.app_assertion_holds,
		broken: m.app_assertion_broken,
		unknown: m.app_assertion_unknown
	};
</script>

<!-- Chrome before data: the header and the tabs do not wait for the controller. -->
<PageHeader title={name}>
	{#snippet actions()}
		{#if detail.data?.domain}
			<a href="https://{detail.data.domain}" target="_blank" rel="noreferrer" class={button}>
				{m.apps_open_site({ domain: detail.data.domain })}<ExternalLink class="size-3.5" />
			</a>
		{/if}
		{#if may('/api/apps/{name}/backup', 'POST')}
			<button type="button" class={button} onclick={() => panel.propose(proposal(m.app_back_up_title({ app: name }), 'post', '/api/apps/{name}/backup', { path: { name } }))}>
				{m.app_detail_back_up_now()}
			</button>
		{/if}
		<!-- Offered only when the catalog has moved it: the preview lists every change. -->
		{#if detail.data && detail.data.catalog_changes.length > 0 && may('/api/apps/{name}/upgrade', 'POST')}
			<button type="button" class={button} onclick={() => panel.propose(proposal(m.app_upgrade_title({ app: name }), 'post', '/api/apps/{name}/upgrade', { path: { name } }))}>
				{m.app_upgrade()}
			</button>
		{/if}
		{#if may('/api/apps/{name}', 'DELETE')}
			<button type="button" class={danger} onclick={() => panel.propose(proposal(m.app_remove_title({ app: name }), 'delete', '/api/apps/{name}', { path: { name } }))}>
				{m.app_remove()}
			</button>
		{/if}
	{/snippet}
</PageHeader>
<div class="mb-6">
	<nav class="flex gap-1 overflow-x-auto overflow-y-hidden border-b border-border">
		{#each tabs as t (t)}
			<a
				href="/apps/{name}{t === 'overview' ? '' : `/${t}`}"
				aria-current={t === tab ? 'page' : undefined}
				class={['-mb-px border-b-2 px-3 py-2 text-sm', t === tab ? 'border-accent font-medium' : 'border-transparent text-muted-text hover:text-text']}
				>{labels[t]()}</a
			>
		{/each}
	</nav>
</div>

<Loaded resource={detail} back="/apps">
	{#snippet children(d)}
		{#if tab === 'overview'}
			{@render overview(d)}
		{:else if tab === 'config'}
			{@render config(d)}
		{:else if tab === 'backups'}
			{@render backups(d)}
		{:else if tab === 'history'}
			{@render history(d)}
		{:else}
			{@const _: never = tab}
		{/if}
	{/snippet}
</Loaded>

{#snippet overview(d: NonNullable<typeof detail.data>)}
	<div class="grid gap-4 lg:grid-cols-3">
		<div class="flex flex-col gap-4 lg:col-span-2">
			{#if d.diagnostic !== null && (d.diagnostic.links.length > 0 || d.diagnostic.unknown_cause)}
				<Card title={m.app_diagnosis()}>
					<ol class="space-y-2 border-l-2 border-critical pl-4">
						{#each d.diagnostic.links as link, i (i)}
							<li class="text-sm">{link.finding}</li>
						{/each}
					</ol>
					{#if d.diagnostic.unknown_cause}<p class="mt-3 text-sm text-attention">{m.app_unknown_cause()}</p>{/if}
					{#if d.diagnostic.remedy}<p class="mt-3 text-sm font-medium">{m.app_remedy({ remedy: d.diagnostic.remedy })}</p>{/if}
				</Card>
			{/if}

			<Card>
				<dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
					<dt class="text-muted-text">{m.app_detail_status()}</dt><dd>{d.summary.status}</dd>
					<dt class="text-muted-text">{m.app_detail_replicas()}</dt>
					<dd class="flex flex-wrap items-center gap-3">
						{m.app_detail_running_desired({ running: d.replicas.live, desired: d.replicas.wanted })}
						{#if may('/api/apps/{name}/scale', 'POST')}
							<!-- Changed where the number is, not in a card of actions further down. -->
							<form
								class="flex flex-wrap items-center gap-2"
								onsubmit={(e) => {
									e.preventDefault();
									if (replicas === undefined || replicas < 1) return;
									void panel.propose(proposal(m.app_scale_title({ app: name, count: replicas }), 'post', '/api/apps/{name}/scale', { path: { name }, body: { replicas } }));
								}}
							>
								<input type="number" min="1" max={limits.ScaleRequest.replicas.maximum} step="1" required bind:value={replicas} aria-label={m.app_scale_label()} placeholder={String(d.replicas.wanted)} class={[input, 'w-20 py-0.5']} />
								{#if replicas !== undefined && replicas >= 1 && replicas <= limits.ScaleRequest.replicas.maximum}
									<button type="submit" class={[button, 'py-0.5']}>{m.app_scale_preview()}</button>
								{/if}
							</form>
							{#if replicas === 0}<span class="text-attention">{m.app_scale_zero()}</span>
							{:else if replicas !== undefined && replicas !== null && (replicas < 0 || replicas > limits.ScaleRequest.replicas.maximum)}
								<span class="text-critical">{m.field_between({ min: 1, max: limits.ScaleRequest.replicas.maximum })}</span>{/if}
						{/if}
					</dd>
					<dt class="text-muted-text">{m.app_detail_image()}</dt><dd class="font-mono text-xs break-all">{d.image ?? d.summary.image}</dd>
					<dt class="text-muted-text">{m.app_detail_last_backup()}</dt>
					<dd>
						{#if !d.summary.holds_data}
							<span class="text-muted-text">{m.backups_nothing_to_back_up()}</span>
						{:else if d.coverage !== null && d.coverage.per_destination.length > 0}
							<!-- Per destination: the freshest copy alone hides the dead one beside it. -->
							<span class="flex flex-wrap gap-x-4">
								{#each d.coverage.per_destination as [dest, age] (dest)}
									<span><span class="text-muted-text">{dest}</span> <span class={age === null ? 'text-critical' : undefined}>{age === null ? m.app_detail_never() : duration(age)}</span></span>
								{/each}
							</span>
						{:else}
							{d.summary.last_backup_secs === null ? m.app_detail_never() : duration(d.summary.last_backup_secs)}
						{/if}
					</dd>
					<dt class="text-muted-text">{m.app_detail_last_verification()}</dt>
					<dd>{d.summary.last_verification_secs === null ? m.duration_never_verified() : duration(d.summary.last_verification_secs)}</dd>
				</dl>
			</Card>

			{#if d.tasks.length > 0}
				<Card title={m.app_detail_placement()}>
					<ul class="space-y-1.5 text-sm">
						{#each d.tasks as task (task.id)}
							<li class={task.failed ? 'text-critical' : ''}>
								{m.app_detail_replica_of_node({ slot: String(task.slot ?? '?'), node: task.node ?? m.app_detail_unknown_node(), state: task.state })}
								{#if task.explanation}<span class="block text-muted-text">{task.explanation}</span>{/if}
							</li>
						{/each}
					</ul>
				</Card>
			{/if}
		</div>

		<div class="flex flex-col gap-4">
			{#if d.assertions.length > 0}
				<Card title={m.app_assertions()}>
					<p class="{muted}">{m.app_assertions_explanation()}</p>
					<code class="mt-1 mb-3 block {code}">{m.app_assertions_command({ app: name })}</code>
					<ul class="space-y-2 text-sm">
						{#each d.assertions as a (a.id)}
							<li>
								<div class="flex flex-wrap items-start justify-between gap-2">
									<span class="min-w-0 grow basis-48">{a.holds}</span>
									<Mark attention={a.attention} label={verdicts[a.verdict]()} />
								</div>
								{#if a.verdict !== 'holds'}<span class="block text-xs text-muted-text wrap-anywhere">{a.observed}</span>{/if}
								{#if a.fix}<p class="mt-1 text-xs wrap-anywhere"><span class="font-medium">{m.app_assertion_fix()}</span> {a.fix}</p>{/if}
							</li>
						{/each}
					</ul>
				</Card>
			{/if}
			{#if d.jobs.length > 0}
				<Card title={m.app_jobs()}>
					<p class="{muted}">{m.app_jobs_explanation()}</p>
					<code class="mt-1 mb-3 block {code} wrap-anywhere">{m.app_jobs_command({ app: name, job: d.jobs[0]?.id ?? '' })}</code>
					<ul class="space-y-2 text-sm">
						{#each d.jobs as j (j.id)}
							<li>
								<div class="flex flex-wrap items-start justify-between gap-2">
									<span class="min-w-0 grow basis-48">{j.does} <span class="text-muted-text">· {j.every === 'week' ? m.app_job_every_week() : m.app_job_every_day()}</span></span>
									<Mark attention={j.attention} label={j.succeeded === null ? m.app_job_waiting() : j.succeeded ? m.app_job_succeeded() : m.app_job_failed()} />
								</div>
								<span class="block text-xs text-muted-text">
									{#if j.last_run_at === null}{m.app_job_never_run()}{:else}{m.app_job_last_run({ at: when(j.last_run_at) })}{#if j.next_run_at !== null} · {m.app_job_next_run({ at: when(j.next_run_at) })}{/if}{/if}
								</span>
								{#if j.succeeded === false && j.output}<code class="mt-1 block {code} wrap-anywhere">{j.output}</code>{/if}
							</li>
						{/each}
					</ul>
				</Card>
			{/if}
			{#if d.guides.length > 0}
				<Card title={m.app_detail_manual_actions()} href="/todo">
					<ul class="space-y-1.5 text-sm">
						{#each d.guides as g (g.id)}
							<li>{g.title} {#if g.blocking}<span class="text-critical">· {m.app_detail_blocking()}</span>{/if}</li>
						{/each}
					</ul>
				</Card>
			{/if}
		</div>
	</div>
{/snippet}

{#snippet config(d: NonNullable<typeof detail.data>)}
	{#if d.capabilities.length === 0 && d.volumes.length === 0 && d.env.length === 0}
		<p class={muted}>{m.app_detail_nothing_to_configure()}</p>
	{/if}
	<div class="grid gap-4 lg:grid-cols-2">
		{#if d.capabilities.length > 0}
			<Card title={m.app_detail_what_was_provisioned()}>
				<ul class="list-disc space-y-1 pl-5 text-sm">{#each d.capabilities as c, i (i)}<li>{need(c)}</li>{/each}</ul>
			</Card>
		{/if}
		{#if d.volumes.length > 0}
			<Card title={m.app_detail_volumes()}>
				<ul class="space-y-1.5 text-sm">
					{#each d.volumes as v (v.name)}
						<li class="flex flex-wrap justify-between gap-2">
							<span class="font-mono text-xs">{m.app_detail_name_and_path({ name: v.name, path: v.path })}</span>
							<span class={v.backup ? 'text-ok' : 'text-critical'}>
								{v.backup ? m.app_detail_backed_up() : m.app_detail_not_backed_up()}{v.sqlite ? ` · ${m.app_detail_sqlite()}` : ''}
							</span>
						</li>
					{/each}
				</ul>
			</Card>
		{/if}
		{#if d.env.length > 0}
			<Card title={m.app_detail_environment_variables()}>
				<p class="mb-2 {muted}">{m.app_detail_env_explanation()}</p>
				<!-- A key never wraps by itself, and the longest set the page's width: on a
				     phone each value goes under its key. -->
				<dl class="grid gap-x-4 gap-y-1 font-mono text-xs sm:grid-cols-[auto_1fr]">
					{#each d.env as [k, v] (k)}<dt class="wrap-anywhere">{k}</dt><dd class="mb-1.5 break-all text-muted-text sm:mb-0">{v}</dd>{/each}
				</dl>
			</Card>
		{/if}
	</div>
	{#if d.manifest !== null}
		<div class="mt-4">
			<Card title={m.app_detail_manifest_frozen()}>
				<p class="mb-2 {muted}">{m.app_detail_manifest_frozen_explanation()}</p>
				<!-- It scrolls sideways under a long line (Vaultwarden's password policy):
				     reachable by keyboard, or the end of that line is not. -->
				<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
				<pre tabindex="0" aria-label={m.app_detail_manifest_frozen()} class="{code} overflow-x-auto whitespace-pre">{d.manifest}</pre>
			</Card>
		</div>
	{/if}
{/snippet}

{#snippet backups(d: NonNullable<typeof detail.data>)}
	<div class="grid gap-4 lg:grid-cols-2">
		{#if d.restorability !== null}
			{@const r = d.restorability}
			<Card title={m.app_detail_if_i_lose_everything_now()}>
				<div class="flex flex-wrap items-start justify-between gap-2">
					<p class="min-w-0 grow basis-48 text-sm font-medium">{r.verdict}</p>
					<Mark attention={r.attention} />
				</div>
				<p class="mt-2 {muted}">{m.app_detail_confidence({ explanation: r.confidence_explanation })}</p>
				{#if r.remedies.length > 0}
					<ul class="mt-2 list-disc space-y-1 pl-5 text-sm">{#each r.remedies as x (x)}<li>{x}</li>{/each}</ul>
				{/if}
			</Card>
		{/if}
		{#if d.coverage !== null}
			<Card title={m.app_detail_coverage()}>
				<div class="flex flex-wrap items-start justify-between gap-2">
					<p class="min-w-0 grow basis-48 text-sm">{coverage(d.coverage.coverage)}</p>
					<Mark attention={d.coverage.attention} />
				</div>
				<p class="mt-3 mb-1 text-xs font-medium text-muted-text">{m.app_per_destination()}</p>
				<ul class="space-y-1 text-sm">
					{#each d.coverage.per_destination as [dest, age] (dest)}
						<li class="flex justify-between gap-2"><span>{dest}</span><span class="text-muted-text">{age === null ? m.app_detail_never() : duration(age)}</span></li>
					{/each}
				</ul>
			</Card>
		{/if}
	</div>
	<div class="mt-4">
		<Card title={m.app_detail_recent_runs()}>
			{#if d.backups.length === 0}
				<p class={muted}>{m.app_detail_no_backup_recorded()}</p>
				<code class="mt-2 block {code}">{m.app_detail_backup_run_command()}</code>
			{/if}
			<ul class="space-y-1.5 text-sm">
				{#each d.backups as run, i (i)}
					<li class="flex flex-wrap justify-between gap-2">
						<span>{m.app_detail_run_kind({ kind: run.kind, to_destination: run.destination === null ? '' : m.app_detail_to_destination({ destination: run.destination }) })}</span>
						<span class={run.succeeded ? 'text-muted-text' : 'text-critical'}>
							{run.succeeded ? when(run.when) : m.app_failed_run({ error: run.error ?? '' })}
						</span>
					</li>
				{/each}
			</ul>
		</Card>
	</div>
{/snippet}

{#snippet history(d: NonNullable<typeof detail.data>)}
	<div class="grid gap-4 lg:grid-cols-2">
		<Card title={m.app_detail_what_changed_in_manifest()}>
			<Loaded resource={versions} empty={m.app_detail_no_manifest_history()}>
				{#snippet children(list)}
					<ol class="space-y-4">
						{#each list as v, i (i)}
							<li>
								<p class="text-sm"><span class="font-mono text-xs text-muted-text">{v.reference}</span> {v.subject}</p>
								{#if v.diff.length === 0}
									<p class={muted}>{v.origin ? m.app_detail_first_known_version() : m.app_detail_no_manifest_change()}</p>
								{:else}
									<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
									<pre tabindex="0" aria-label={v.reference} class="{code} mt-1 overflow-x-auto whitespace-pre">{#each v.diff as line, j (j)}<span class={line.startsWith('+') ? 'text-ok' : line.startsWith('-') ? 'text-critical' : ''}>{line}{'\n'}</span>{/each}</pre>
								{/if}
							</li>
						{/each}
					</ol>
				{/snippet}
			</Loaded>
		</Card>
		<Card title={m.journal_title()} href="/audit">
			{#if d.journal.length === 0}<p class={muted}>{m.app_detail_no_action_recorded()}</p>{/if}
			<ul class="space-y-1.5 text-sm">
				{#each d.journal as entry (entry.id)}
					<li>
						<span class="font-medium">{entry.action}</span> · {entry.actor} · <span class="text-muted-text">{when(entry.at)}</span>
						{#if entry.detail}<span class="block text-muted-text">{entry.detail}</span>{/if}
					</li>
				{/each}
			</ul>
		</Card>
	</div>
{/snippet}
