<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import Card from '#lib/ui/Card.svelte';
	import { button, muted } from '#lib/ui/styles.ts';

	// Plain links: under cookie authentication a download carries the session like any
	// other request, which the native window's bearer token never could.
	const exports = [
		['audit', m.settings_export_audit],
		['accounts', m.settings_export_accounts],
		['backups', m.settings_export_backups]
	] as const;
</script>

<div class="grid gap-4 lg:grid-cols-2">
	<Card title={m.security_runbook()}>
		<p class="mb-2 {muted}">{m.security_runbook_explanation()}</p>
		<p class="mb-3 text-sm text-attention">{m.security_runbook_storage_reminder()}</p>
		<a href="/api/runbook" download="runbook.md" class={button}>{m.settings_runbook_download()}</a>
	</Card>
	<Card title={m.page_settings_exports()}>
		<p class="mb-3 {muted}">{m.settings_exports_explanation()}</p>
		<ul class="space-y-2">
			{#each exports as [what, label] (what)}
				<li class="flex flex-wrap items-center justify-between gap-2 text-sm">
					<span>{label()}</span>
					<a href="/api/export/{what}" download class={button}>{m.export_csv()}</a>
				</li>
			{/each}
		</ul>
	</Card>
</div>
