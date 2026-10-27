<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';

	/**
	 * A detail naming something that does not exist. A verdict, not a moment: retrying
	 * asks the same question and gets the same answer, so it offers the list instead.
	 */
	let { back = '/' }: { back?: string } = $props();
</script>

<div role="alert" class="flex flex-wrap items-center gap-3 py-6">
	<p class="min-w-0 grow basis-48 text-sm">{m.state_gone()}</p>
	<a href={back} class="text-sm text-accent hover:underline">{back === '/' ? m.state_go_home() : m.state_back_to_list()}</a>
</div>
