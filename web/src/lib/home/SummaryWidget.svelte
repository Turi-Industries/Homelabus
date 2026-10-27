<script lang="ts">
	import { allowed } from '#lib/api/rights.ts';
	import { megabytes, percent } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import { me } from '#lib/session.ts';
	import { histories, historyOf, type History } from '#lib/home/history.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Sparkline from '#lib/ui/Sparkline.svelte';

	/**
	 * The installation in a line of figures. Each says what IS — machines, applications,
	 * load, storage — and none counts what is wrong: that is the problems' card alone.
	 * Each figure is a link to the page it summarises.
	 */
	const can = $derived(me().data?.can);
	const nodes = read('/api/nodes');
	const apps = read('/api/apps');
	const exposure = read('/api/exposure');
	$effect(() => nodes.watch());
	$effect(() => (allowed(can, '/api/apps', 'GET') ? apps.watch() : undefined));
	$effect(() => (allowed(can, '/api/exposure', 'GET') ? exposure.watch() : undefined));

	// The trends under the figures: the period shown, all machines averaged.
	const all = $derived(histories());
	$effect(() => all.watch());
	const cpuPast = $derived(historyOf(all.data, 'cpu'));
	const memoryPast = $derived(historyOf(all.data, 'memory'));
	const appsPast = $derived(historyOf(all.data, 'apps_running'));

	/** Every machine's curve as one: the mean at each moment any of them was measured. */
	function averaged(h: History | undefined): { points: [number, number][]; h: History } | undefined {
		if (h === undefined || h.lines.length === 0) return undefined;
		const at = new Map<number, number[]>();
		for (const l of h.lines) for (const [t, v] of l.points) at.set(t, [...(at.get(t) ?? []), v]);
		const points = [...at].sort(([a], [b]) => a - b).map(([t, vs]): [number, number] => [t, vs.reduce((x, y) => x + y, 0) / vs.length]);
		return points.length > 1 ? { points, h } : undefined;
	}

	const up = $derived(nodes.data?.filter((n) => n.reachable));
	const mean = (values: (number | null)[]) => {
		const known = values.filter((v) => v !== null);
		return known.length === 0 ? undefined : known.reduce((a, b) => a + b, 0) / known.length;
	};
	const disks = $derived(up?.flatMap((n) => n.disks));

	// 🔴 A figure says nothing until its source is read: "0 running" while the list is
	// still on its way is a false all-quiet.
	const figures = $derived([
		{ value: up && nodes.data ? `${up.length} / ${nodes.data.length}` : undefined, caption: m.summary_machines(), href: '/nodes' },
		{
			value: apps.data ? `${apps.data.filter((a) => a.status === 'running').length} / ${apps.data.length}` : undefined,
			caption: m.summary_apps(),
			href: '/apps',
			trend: averaged(appsPast),
			offered: allowed(can, '/api/apps', 'GET')
		},
		{ value: up ? fraction(mean(up.map((n) => n.cpu_busy))) : undefined, caption: m.summary_cpu(), href: '/nodes', trend: averaged(cpuPast), ratio: true },
		{ value: up ? fraction(mean(up.map((n) => n.memory_used))) : undefined, caption: m.summary_memory(), href: '/nodes', trend: averaged(memoryPast), ratio: true },
		{
			value: disks ? megabytes(disks.reduce((a, d) => a + d.total_mb - d.free_mb, 0)) : undefined,
			href: '/nodes',
			caption: disks ? m.summary_storage({ total: megabytes(disks.reduce((a, d) => a + d.total_mb, 0)) }) : m.summary_storage({ total: '…' })
		},
		{
			value: exposure.data ? String(exposure.data.filter((e) => e.public).length) : undefined,
			caption: m.summary_public(),
			href: '/exposure',
			offered: allowed(can, '/api/exposure', 'GET')
		}
	]);

	function fraction(v: number | undefined): string {
		return v === undefined ? '—' : percent(v);
	}
</script>

<Card fill title={m.widget_summary()}>
	<ul class="flex h-full flex-wrap content-stretch gap-2">
		{#each figures.filter((f) => f.offered !== false) as f (f.caption)}
			<li class="flex min-w-0 grow basis-32">
				<a href={f.href} class="flex min-w-0 grow flex-col justify-center rounded-md bg-raised-surface px-3 py-2 hover:ring-1 hover:ring-border">
					<span class="text-2xl font-semibold tabular-nums" aria-busy={f.value === undefined}>{f.value ?? '—'}</span>
					<span class="truncate text-xs text-muted-text" title={f.caption}>{f.caption}</span>
					{#if f.trend !== undefined}
						<div class="mt-1">
							<Sparkline quiet lines={[{ points: f.trend.points, name: f.caption }]} from={f.trend.h.from} to={f.trend.h.now} step={f.trend.h.step_s} max={f.ratio ? 1 : undefined} format={String} label={f.caption} height={20} />
						</div>
					{/if}
				</a>
			</li>
		{/each}
	</ul>
</Card>
