<script lang="ts">
	import { limits } from '#lib/api/limits.ts';
	import { panel, type ActionResult } from '#lib/action.svelte.ts';
	import { api, type Schemas } from '#lib/api/client.ts';
	import { refusal } from '#lib/resource.svelte.ts';
	import { copy as write } from '#lib/clipboard.ts';
	import { m } from '#lib/paraglide/messages.js';
	import DeviceSetup from './DeviceSetup.svelte';
	import Qr from './Qr.svelte';

	/**
	 * The action panel: the preview the controller computed, then — only after it was
	 * read — the button that applies it. Three beats: ask, read the plan, confirm the plan.
	 */
	let dialog = $state<HTMLDialogElement>();
	let confirmed = $state('');
	let planName = $state('');
	let planNote = $state<string | undefined>();
	let copied = $state<'copied' | 'selected' | null>(null);

	const stage = $derived(panel.stage);
	const result = $derived<ActionResult | undefined>(
		'result' in stage ? stage.result : undefined
	);
	const target = $derived(result?.confirmation_required ?? null);
	const canApply = $derived(
		stage.kind === 'previewed' &&
			stage.result.applicable &&
			(target === null || confirmed === target)
	);

	$effect(() => {
		if (stage.kind === 'closed') {
			dialog?.close();
		} else if (dialog && !dialog.open) {
			confirmed = '';
			planName = '';
			planNote = undefined;
			copied = null;
			dialog.showModal();
		}
	});

	// The text sits in the `<code>` beside the button: selected when there is no clipboard.
	async function copy(text: string, pressed: HTMLElement) {
		copied = await write(text, pressed.parentElement?.querySelector('code') ?? null);
	}

	async function record() {
		if (!('proposal' in stage) || result === undefined || stage.proposal.plan === null) return;
		const { method, path, body } = stage.proposal.plan;
		const name = planName.trim();
		const { error, response } = await api.POST('/api/plans', {
			body: { name, method, path, body: body ?? undefined, summary: result.summary, note: null }
		});
		planNote = response.ok ? m.action_recorded({ name }) : refusal(error, response);
	}

	const stepWords = {
		planned: m.action_step_planned,
		done: m.action_step_done,
		failed: m.action_step_failed,
		unimplemented: m.action_step_unimplemented
	};
	const stepTone = {
		planned: 'text-muted-text',
		done: 'text-ok',
		failed: 'text-critical',
		unimplemented: 'text-attention'
	};
</script>

<dialog
	bind:this={dialog}
	aria-label={m.action_panel_label()}
	onclose={() => panel.close()}
	class="m-0 ml-auto h-dvh max-h-dvh w-full max-w-xl overflow-y-auto border-l border-border bg-surface p-0 text-text backdrop:bg-background/70"
>
	{#if stage.kind !== 'closed'}
		<div class="flex flex-col gap-5 p-6">
			<header class="flex items-start justify-between gap-4">
				<div class="min-w-0">
					<h2 class="text-lg font-semibold">{stage.proposal.title}</h2>
					{#if stage.kind === 'previewed'}
						<p class="text-sm text-muted-text">{m.action_preview_nothing_changed_yet()}</p>
					{/if}
				</div>
				<button
					type="button"
					class="rounded-md border border-border px-3 py-1 text-sm hover:bg-raised-surface"
					onclick={() => panel.close()}>{m.action_close()}</button
				>
			</header>

			{#if stage.kind === 'previewing'}
				<p class="text-sm text-muted-text" aria-busy="true">{m.action_previewing()}</p>
			{:else if stage.kind === 'failed'}
				<p role="alert" class="rounded-lg border border-critical p-3 text-sm text-critical">
					{m.action_action_could_not_be_started()} — {stage.error}
				</p>
			{:else if result !== undefined}
				<p class="font-medium">{result.summary}</p>

				{#if stage.kind === 'applied'}
					{@const outcome = result.outcome}
					<p
						role="status"
						class={[
							'rounded-lg border p-3 text-sm font-medium',
							outcome.kind === 'done' ? 'border-ok text-ok' : '',
							outcome.kind === 'failed' ? 'border-critical text-critical' : '',
							outcome.kind === 'incomplete' || outcome.kind === 'preview'
								? 'border-attention text-attention'
								: ''
						]}
					>
						{#if outcome.kind === 'done'}
							{m.action_outcome_done()}
						{:else if outcome.kind === 'failed'}
							{m.action_outcome_failed({ count: outcome.steps })}
						{:else if outcome.kind === 'incomplete'}
							{m.action_outcome_incomplete({ count: outcome.steps })}
						{:else}
							{m.action_preview_nothing_changed_yet()}
						{/if}
					</p>
				{/if}

				{#if 'link' in result && typeof result.link === 'string'}
					{@render once(result.link)}
				{/if}

				{#if 'setup' in result && result.setup}
					<DeviceSetup setup={result.setup as Schemas['DeviceSetup']} />
				{/if}

				{#if result.blockers.length > 0}
					<section class="rounded-lg border border-critical p-3">
						<h3 class="text-sm font-semibold text-critical">{m.action_blockers()}</h3>
						<ul class="mt-2 list-disc space-y-1 pl-5 text-sm">
							{#each result.blockers as blocker (blocker)}<li>{blocker}</li>{/each}
						</ul>
					</section>
				{/if}

				{#if result.warnings.length > 0}
					<section class="rounded-lg border border-attention p-3">
						<h3 class="text-sm font-semibold text-attention">{m.action_warnings()}</h3>
						<ul class="mt-2 list-disc space-y-1 pl-5 text-sm">
							{#each result.warnings as warning (warning)}<li>{warning}</li>{/each}
						</ul>
					</section>
				{/if}

				{#if result.steps.length > 0}
					<section>
						<h3 class="text-sm font-semibold">{m.action_what_will_be_done_in_order()}</h3>
						<ol class="mt-2 space-y-2">
							{#each result.steps as step, i (i)}
								<li class="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-sm">
									<span class="w-6 shrink-0 text-right text-muted-text tabular-nums">{i + 1}.</span>
									<span class="min-w-0 grow basis-48">
										{step.description}
										{#if step.error}<span class="block text-critical">{step.error}</span>{/if}
									</span>
									<span class={['text-xs font-medium', stepTone[step.state]]}>
										{stepWords[step.state]()}
									</span>
								</li>
							{/each}
						</ol>
					</section>
				{/if}

				<section>
					<h3 class="text-sm font-semibold">{m.action_equivalent_command_line()}</h3>
					<div class="mt-2 flex flex-wrap items-center gap-2">
						<code class="min-w-0 grow basis-48 rounded-md bg-raised-surface px-3 py-2 font-mono text-xs whitespace-pre-wrap wrap-anywhere">
							{result.cli_command}
						</code>
						<button
							type="button"
							class="rounded-md border border-border px-3 py-1 text-sm hover:bg-raised-surface"
							onclick={(e) => copy(result.cli_command, e.currentTarget)}
							>{copied === null ? m.action_copy() : copied === 'copied' ? m.action_copied() : m.action_copy_selected()}</button
						>
					</div>
				</section>

				{#if stage.kind === 'passkey'}
					<section class="flex flex-col items-start gap-3 border-t border-border pt-4">
						<!-- Not "destructive": a passkey also guards what takes nothing away — a
						     device's password, a role given, a node paused. -->
						<p class="text-sm font-semibold text-critical">{m.action_passkey_heading()}</p>
						<p class="text-sm">{m.action_passkey_needed()}</p>
						{#if stage.refused !== null}
							<p role="alert" class="text-sm text-critical">
								{#if stage.refused === 'blocked'}
									{m.action_passkey_blocked()}
								{:else if stage.refused === 'timeout'}
									{m.action_passkey_timeout()}
								{:else}
									{m.action_passkey_refused({ error: stage.refused.idp })}
								{/if}
							</p>
						{/if}
						{#if stage.waiting}
							<p class="text-sm text-muted-text" aria-busy="true">{m.action_passkey_waiting()}</p>
						{/if}
						<button
							type="button"
							class="rounded-md border-2 border-critical px-4 py-2 text-sm font-semibold text-critical"
							onclick={() => void panel.presentPasskey()}>{m.action_passkey_present()}</button
						>
					</section>
				{/if}

				{#if stage.kind === 'previewed' || stage.kind === 'applying'}
					{#if result.applicable}
						<form
							class="flex flex-col gap-3 border-t border-border pt-4"
							onsubmit={(e) => {
								e.preventDefault();
								void panel.apply(target === null ? null : confirmed);
							}}
						>
							{#if target !== null}
								<p class="text-sm font-semibold text-critical">{m.action_destructive_operation()}</p>
								<p class="text-sm">{m.action_confirmation_explanation({ target })}</p>
								<label class="flex flex-col gap-1 text-sm">
									{m.action_type_to_confirm({ target })}
									<input
										bind:value={confirmed}
										maxlength={limits.Confirmation.confirmed.maxLength}
										autocomplete="off"
										spellcheck="false"
										class="rounded-md border border-border bg-background px-3 py-2 font-mono"
									/>
								</label>
							{/if}
							<button
								type="submit"
								disabled={!canApply}
								class={[
									'self-start rounded-md px-4 py-2 text-sm font-semibold disabled:opacity-50',
									target === null ? 'bg-accent text-on-accent' : 'border-2 border-critical text-critical'
								]}
							>
								{#if stage.kind === 'applying'}
									{m.action_applying()}
								{:else if target !== null}
									{m.action_apply_irreversible()}
								{:else}
									{m.action_apply()}
								{/if}
							</button>
						</form>
					{/if}

					{#if stage.proposal.plan !== null}
					<form
						class="flex flex-col gap-2 border-t border-border pt-4"
						onsubmit={(e) => {
							e.preventDefault();
							void record();
						}}
					>
						<label class="text-sm font-semibold" for="plan-name">{m.action_prepare_for_later()}</label>
						<div class="flex flex-wrap gap-2">
							<input
								id="plan-name"
								bind:value={planName}
								maxlength={limits.PlanRequest.name.maxLength}
								placeholder={m.action_plan_name_hint()}
								class="min-w-0 grow basis-48 rounded-md border border-border bg-background px-3 py-1.5 text-sm"
							/>
							<button
								type="submit"
								disabled={planName.trim() === ''}
								class="rounded-md border border-border px-3 py-1 text-sm hover:bg-raised-surface disabled:opacity-50"
								>{m.action_record()}</button
							>
						</div>
						{#if planNote !== undefined}<p class="text-sm text-muted-text" role="status">{planNote}</p>{/if}
					</form>
					{/if}
				{/if}
			{/if}
		</div>
	{/if}
</dialog>

{#snippet once(link: string)}
	<section class="flex flex-col items-start gap-3 rounded-lg border border-accent p-3">
		<p class="text-sm">{m.action_link_shown_once_explanation()}</p>
		<div class="flex w-full flex-wrap items-center gap-2">
			<code class="min-w-0 grow basis-48 rounded-md bg-raised-surface px-3 py-2 font-mono text-xs break-all">{link}</code>
			<button type="button" class="rounded-md border border-border px-3 py-1 text-sm hover:bg-raised-surface" onclick={(e) => copy(link, e.currentTarget)}>
				{copied === null ? m.action_copy() : copied === 'copied' ? m.action_copied() : m.action_copy_selected()}
			</button>
		</div>
		<Qr value={link} label={link} />
	</section>
{/snippet}
