<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import { copy as write } from '#lib/clipboard.ts';
	import { mobileconfig } from '#lib/mobileconfig.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { button, code, muted } from './styles.ts';

	/**
	 * What a device is set up with, the one time it is known: the panel shows it after
	 * the password is made, and nothing can show it again.
	 */
	let { setup }: { setup: Schemas['DeviceSetup'] } = $props();

	let copied = $state<string | null>(null);

	const fields = $derived([
		['server', m.device_setup_server(), setup.server],
		['user', m.device_setup_user(), setup.user],
		['password', m.device_setup_password(), setup.password]
	] as const);

	// The text sits in the `<code>` beside the button: selected when there is no clipboard.
	async function copy(key: string, text: string, pressed: HTMLElement) {
		const how = await write(text, pressed.parentElement?.querySelector('code') ?? null);
		copied = how === 'copied' ? key : null;
	}

	// Built in this page and handed over as a file: the password reaches no URL, and no
	// request the controller could log.
	function download() {
		const blob = new Blob([mobileconfig(setup)], { type: 'application/x-apple-aspen-config' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `${setup.device.replace(/[^\p{L}\p{N}._-]+/gu, '-')}.mobileconfig`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<section class="flex flex-col gap-3 rounded-lg border border-accent p-3">
	<p class="text-sm">{m.device_setup_explanation()}</p>
	<dl class="flex flex-col gap-2">
		{#each fields as [key, label, value] (key)}
			<div class="flex flex-wrap items-center gap-2">
				<dt class="w-full text-xs text-muted-text">{label}</dt>
				<dd class="contents">
					<code class="min-w-0 grow basis-48 {code}">{value}</code>
					<button type="button" class={button} onclick={(e) => copy(key, value, e.currentTarget)}>
						{copied === key ? m.action_copied() : m.action_copy()}
					</button>
				</dd>
			</div>
		{/each}
	</dl>
	<div class="flex flex-col items-start gap-2 border-t border-border pt-3">
		<p class={muted}>{m.device_setup_apple()}</p>
		<button type="button" class={button} onclick={download}>{m.device_setup_apple_download()}</button>
	</div>
	<p class={muted}>{m.device_setup_android({ server: setup.server })}</p>
	<p class={muted}>{m.device_setup_mail({ server: setup.server })}</p>
</section>
