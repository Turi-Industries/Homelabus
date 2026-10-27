<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';

	/**
	 * The AGPL (§13) has whoever runs a modified copy for others offer them its source:
	 * a link to the one this controller was built from, which the build names.
	 */
	const build = read('/healthz');
	$effect(() => build.watch());
</script>

{#if build.data}
	<a href={build.data.source} rel="noopener" class="block truncate text-xs text-muted-text underline hover:text-text">
		{m.nav_source({ version: build.data.version })}
	</a>
{/if}
