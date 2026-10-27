<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import { megabytes } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import Gauge from './Gauge.svelte';

	let { disk }: { disk: Schemas['DiskSummary'] } = $props();

	// The server's pressure step (0 healthy … 4 critical) decides the colour: a disk has
	// its own thresholds, and the gauge does not invent them.
	const tone = $derived(disk.pressure >= 4 ? 'bg-critical' : disk.pressure >= 2 ? 'bg-attention' : 'bg-accent');
</script>

<div>
	<Gauge label={disk.path} value={disk.used} {tone} />
	<p class="mt-0.5 text-xs text-muted-text">{m.nodes_free_space({ size: megabytes(disk.free_mb) })} / {megabytes(disk.total_mb)}</p>
</div>
