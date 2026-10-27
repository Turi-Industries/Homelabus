<script lang="ts">
	import { copy as write } from '#lib/clipboard.ts';
	import { TYPED } from '#lib/fields.ts';
	import { m } from '#lib/paraglide/messages.js';
	import Card from '#lib/ui/Card.svelte';
	import { button, code, input, muted } from '#lib/ui/styles.ts';

	/**
	 * Assembles `hlb storage init` and `hlb storage export` for the person to run on the
	 * storage machine — it executes nothing: what is deliberately not automated stays so.
	 */
	let pool = $state('');
	let root = $state('');
	let network = $state('');
	let copied = $state<{ text: string; how: 'copied' | 'selected' } | null>(null);

	const poolFlag = $derived(pool.trim() === '' ? '' : ` --pool ${pool.trim()}`);
	const rootValue = $derived(root.trim() === '' ? 'apps' : root.trim());
	// No default network: an empty one stays a visible placeholder, never a guessed CIDR.
	const networkValue = $derived(network.trim() === '' ? '<network>' : network.trim());
	const init = $derived(`hlb storage init${poolFlag} --root ${rootValue} --apply`);
	const exports = $derived(`hlb storage export${poolFlag} --root ${rootValue} --network ${networkValue}`);

	// The one inline error with something true to say: a space splits the pasted command
	// into two arguments, and nothing else would catch it — the server never sees this form.
	const spaced = (value: string) => /\s/.test(value.trim());

	// The command sits in the `<code>` beside the button: selected when there is no clipboard.
	async function copy(text: string, pressed: HTMLElement) {
		copied = { text, how: await write(text, pressed.parentElement?.querySelector('code') ?? null) };
	}
</script>

<div class="flex max-w-3xl flex-col gap-4">
	<p class={muted}>{m.storage_wizard_explanation()}</p>
	{#snippet field(label: string, hint: string, value: string, set: (v: string) => void)}
		<label class="flex flex-col gap-1 text-sm">
			{label}
			<input value={value} maxlength={TYPED} oninput={(e) => set(e.currentTarget.value)} placeholder={hint} autocapitalize="none" spellcheck="false" class={input} />
			{#if spaced(value)}<span class="text-critical">{m.storage_wizard_value_has_a_space()}</span>{/if}
		</label>
	{/snippet}
	{#snippet command(text: string)}
		<div class="mt-3 flex flex-wrap items-center gap-2">
			<code class="min-w-0 grow basis-48 {code}">{text}</code>
			<button type="button" class={button} onclick={(e) => copy(text, e.currentTarget)}
				>{copied?.text !== text ? m.storage_wizard_copy() : copied.how === 'copied' ? m.action_copied() : m.action_copy_selected()}</button
			>
		</div>
	{/snippet}
	<Card title={m.storage_wizard_import_step()}>
		<p class="mb-3 {muted}">{m.storage_wizard_import_explanation()}</p>
		<div class="grid gap-3 sm:grid-cols-2">
			{@render field(m.storage_wizard_pool_label(), m.storage_wizard_pool_hint(), pool, (v) => (pool = v))}
			{@render field(m.storage_wizard_root_label(), 'apps', root, (v) => (root = v))}
		</div>
		{@render command(init)}
	</Card>
	<Card title={m.storage_wizard_export_step()}>
		<p class="mb-3 {muted}">{m.storage_wizard_export_explanation()}</p>
		{@render field(m.storage_wizard_network_label(), m.storage_wizard_network_hint(), network, (v) => (network = v))}
		{@render command(exports)}
	</Card>
</div>
