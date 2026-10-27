<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import type { Column } from '#lib/listing.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read } from '#lib/resource.svelte.ts';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Table from '#lib/ui/Table.svelte';
	import { muted } from '#lib/ui/styles.ts';

	type Secret = Schemas['SecretItem'];
	const secrets = read('/api/secrets');
	const columns: Column<Secret>[] = [
		{ id: 'name', label: m.secrets_column_name, value: (s) => s.name, cell: name },
		{ id: 'purpose', label: m.secrets_column_purpose, value: (s) => s.purpose }
	];
</script>

{#snippet name(s: Secret)}<span class="font-mono">{s.name}</span>{/snippet}

<p class="mb-3 {muted}">{m.secrets_without_value_explanation()}</p>
<Loaded resource={secrets}>
	{#snippet children(list)}
		<Table rows={list} key={(s) => s.name} {columns} search={m.secrets_search()} empty={m.secrets_no_secret_recorded()} />
	{/snippet}
</Loaded>
