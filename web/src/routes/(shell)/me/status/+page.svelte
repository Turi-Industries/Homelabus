<script lang="ts">
	import { read } from '#lib/resource.svelte.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import StatusBoard from '#lib/ui/StatusBoard.svelte';

	const status = read('/api/status');
</script>

<Loaded resource={status}>
	{#snippet children(page)}<StatusBoard {page} />{/snippet}
</Loaded>
