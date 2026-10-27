<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { tone } from '#lib/words.ts';

	type Attention = Schemas['Attention'];
	let { attention, label }: { attention: Attention; label?: string } = $props();

	// The words say it; the colour repeats it. A dot alone would be read only by those
	// who can tell the palette's colours apart.
	const words: Record<Attention, () => string> = {
		ok: m.attention_ok,
		notice: m.attention_notice,
		critical: m.attention_critical
	};
</script>

<!-- A dot and its words, not a pill: a column of pills is a column of borders, and the
     eye stops on every one of them instead of on the few that matter. -->
<span class={['inline-flex shrink-0 items-center gap-1.5 text-sm whitespace-nowrap', attention !== 'ok' && tone[attention].text]}>
	<span aria-hidden="true" class={['size-2 shrink-0 rounded-full', tone[attention].bg]}></span>
	{label ?? words[attention]()}
</span>
