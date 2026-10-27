<script lang="ts">
	import { limits } from '#lib/api/limits.ts';
	import { api } from '#lib/api/client.ts';
	import { duration } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read, refusal } from '#lib/resource.svelte.ts';
	import { may } from '#lib/session.ts';
	import { button, input, primary } from '#lib/ui/styles.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { muted } from '#lib/ui/styles.ts';
	import { ALERT_RULES } from '#lib/vocabulary.ts';

	const alerts = read('/api/alerts');
	const level = {
		unknown: m.alerts_level_unknown,
		info: m.alerts_level_info,
		important: m.alerts_level_important,
		critical: m.alerts_level_critical
	};
	const rank = { critical: 0, notice: 1, ok: 2 };

	// One value, asked once: a choice of whole durations, never a free field whose unit
	// someone has to guess. The server caps a mute at a week; so does the longest choice.
	const lengths = [
		[3_600, () => m.alerts_hours({ count: 1 })],
		[4 * 3_600, () => m.alerts_hours({ count: 4 })],
		[86_400, () => m.alerts_days({ count: 1 })],
		[3 * 86_400, () => m.alerts_days({ count: 3 })],
		[7 * 86_400, () => m.alerts_days({ count: 7 })]
	] as const;

	let muting = $state<string | null>(null);
	// The modal closes by clearing a boolean it is bound to; which rule stays.
	let asking = $state(false);
	let length = $state(4 * 3_600);
	let reason = $state('');
	let failure = $state<string | undefined>();

	// A declaration undone in one click, with no preview by the route's own choice.
	async function mute(rule: string) {
		const { error, response } = await api.POST('/api/alerts/{rule}/mute', {
			params: { path: { rule } },
			body: { for_s: length, reason: reason.trim() }
		});
		failure = response.ok ? undefined : m.alerts_mute_failed({ error: refusal(error, response) });
		if (response.ok) asking = false;
		await alerts.refresh();
	}

	async function unmute(rule: string) {
		const { error, response } = await api.DELETE('/api/alerts/{rule}/mute', { params: { path: { rule } } });
		failure = response.ok ? undefined : m.alerts_mute_failed({ error: refusal(error, response) });
		await alerts.refresh();
	}
</script>

<Card title={m.alerts_title()}>
	<Loaded resource={alerts} empty={m.alerts_no_active_alert()}>
		{#snippet children(list)}
			{@const blind = list.filter((a) => a.level === 'unknown').length}
			{@const silenced = list.filter((a) => a.mute !== null).length}
			<p class="mb-3 {muted}">
				{silenced > 0 ? m.alerts_active_count_with_muted({ count: list.length, muted: silenced }) : m.alerts_active_count({ count: list.length })}
			</p>
			{#if failure}<p role="alert" class="mb-3 text-sm text-critical">{failure}</p>{/if}
			{#if blind > 0}
				<p class="mb-3 rounded-lg border border-critical p-3 text-sm text-critical">
					{m.alerts_rules_cannot_be_evaluated({ rules: blind })}
					{m.alerts_blind_monitoring_explanation()}
				</p>
			{/if}
			<ul>
				{#each [...list].sort((a, b) => rank[a.attention] - rank[b.attention]) as alert (alert.rule)}
					<Row>
						<p class="font-medium">{alert.rule} <span class="text-xs font-normal text-muted-text">· {level[alert.level]()}</span></p>
						<p class="text-sm">{ALERT_RULES[alert.rule]?.() ?? alert.explanation}</p>
						<p class="text-xs text-muted-text">
							{alert.value === null ? m.alerts_no_data() : m.alerts_measured_value({ value: String(alert.value), threshold: String(alert.threshold) })}
							· {m.alerts_for_duration({ duration: duration(alert.since_s) })}
						</p>
						{#if alert.mute !== null}
							<!-- A mute stays visible: hidden, it would be a deleted alert with a timer. -->
							<p class="text-xs text-attention">
								{alert.mute.by === null
									? m.alerts_muted({ remaining: duration(alert.mute.remaining_s) })
									: m.alerts_muted_by({ by: alert.mute.by, remaining: duration(alert.mute.remaining_s) })}
								{#if alert.mute.reason}— {m.alerts_mute_reason_given({ reason: alert.mute.reason })}{/if}
							</p>
						{/if}
						{#snippet aside()}
							<Mark attention={alert.attention} />
							{#if may('/api/alerts/{rule}/mute', 'POST')}
								{#if alert.mute === null}
									<button type="button" class={button} onclick={() => ((muting = alert.rule), (reason = ''), (failure = undefined), (asking = true))}>{m.alerts_mute()}</button>
								{:else}
									<button type="button" class={button} onclick={() => unmute(alert.rule)}>{m.alerts_unmute()}</button>
								{/if}
							{/if}
						{/snippet}
					</Row>
				{/each}
			</ul>
		{/snippet}
	</Loaded>
</Card>

{#if muting !== null}
	{@const rule = muting}
	<Modal bind:open={asking} title={m.alerts_mute_title({ rule })}>
		<form class="flex flex-col gap-3" onsubmit={(e) => (e.preventDefault(), void mute(rule))}>
			<p class="text-sm text-muted-text">{m.alerts_mute_explanation()}</p>
			<label class="flex flex-col gap-1 text-sm">{m.alerts_mute_for()}
				<select bind:value={length} class={input}>
					{#each lengths as [seconds, label] (seconds)}<option value={seconds}>{label()}</option>{/each}
				</select>
			</label>
			<label class="flex flex-col gap-1 text-sm">{m.alerts_mute_reason()}
				<input bind:value={reason} maxlength={limits.MuteRequest.reason.maxLength} required placeholder={m.alerts_mute_reason_hint()} class={input} />
			</label>
			{#if failure}<p role="alert" class="text-sm text-critical">{failure}</p>{/if}
			<button type="submit" class={[primary, 'self-start']} disabled={reason.trim() === ''}>{m.alerts_mute_confirm()}</button>
		</form>
	</Modal>
{/if}
