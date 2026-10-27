<script lang="ts">
	import X from '@lucide/svelte/icons/x';
	import type { Snippet } from 'svelte';
	import { m } from '#lib/paraglide/messages.js';

	/**
	 * What a button opens — a form, a choice, a result — on top of the page, rather than
	 * unfolded into it: unfolded, it pushed down the list it belongs to, or appeared above
	 * a list scrolled past it, out of sight of the button that asked for it.
	 */
	let {
		open = $bindable(false),
		title,
		children
	}: { open?: boolean; title: string; children: Snippet } = $props();

	// No closing on a click beside it, like the action panel: a stray click would take
	// with it what is shown once — a key, a link. Escape and the button close it.
	let dialog = $state<HTMLDialogElement>();

	$effect(() => {
		if (open && dialog && !dialog.open) dialog.showModal();
		else if (!open && dialog?.open) dialog.close();
	});
</script>

<dialog
	bind:this={dialog}
	aria-label={title}
	onclose={() => (open = false)}
	class="m-auto max-h-[calc(100dvh-2rem)] w-[min(32rem,calc(100vw-2rem))] overflow-y-auto rounded-xl border border-border bg-surface p-0 text-text backdrop:bg-background/70"
>
	<!-- Drawn only while open: a closed form keeps no focusable field behind the page. -->
	{#if open}
		<div class="flex flex-col gap-4 p-5">
			<header class="flex items-start justify-between gap-4">
				<h2 class="min-w-0 text-lg font-semibold">{title}</h2>
				<button type="button" aria-label={m.action_close()} class="shrink-0 rounded-md p-1 hover:bg-raised-surface" onclick={() => (open = false)}>
					<X aria-hidden="true" class="size-4" />
				</button>
			</header>
			{@render children()}
		</div>
	{/if}
</dialog>
