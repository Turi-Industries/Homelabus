<script lang="ts">
	import type { Schemas } from '#lib/api/client.ts';
	import { copy as write } from '#lib/clipboard.ts';
	import { when } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { getLocale } from '#lib/paraglide/runtime.js';
	import { read } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import Mark from '#lib/ui/Mark.svelte';
	import Row from '#lib/ui/Row.svelte';
	import { button, code, muted } from '#lib/ui/styles.ts';
	import { caaVerdict, domainAdvice, domainChange, driftSide } from '#lib/words.ts';

	type Seen = Schemas['DomainSeen'];
	const domain = read('/api/domain');

	// Preview by default: the command alone shows what would change, and only the
	// person who read that adds the flag.
	const accept = 'hlb domain accept --apply';
	let copied = $state<'copied' | 'selected' | undefined>(undefined);
	async function copy(pressed: HTMLElement) {
		copied = await write(accept, pressed.parentElement?.querySelector('code') ?? null);
	}

	const list = (v: string[]) => (v.length > 0 ? v.join(', ') : m.domain_none());

	// What a CAA `validationmethods` is judged against: a refusal says which.
	function challenges(a: Schemas['AcmeAccount']): string | undefined {
		if (a.validations.length === 0) return undefined;
		const or = new Intl.ListFormat(getLocale(), { type: 'disjunction' });
		const each = a.validations.map((v) => {
			const methods = or.format(v.methods);
			return v.wildcard ? m.domain_account_by_wildcard({ methods }) : methods;
		});
		return m.domain_account_by({ methods: each.join('; ') });
	}

	function dnssec(dns: Schemas['DomainDns']): string {
		if (dns.ds.length === 0) return m.domain_dnssec_unsigned();
		return dns.validated ? m.domain_dnssec_validates() : m.domain_dnssec_broken();
	}
</script>

{#snippet field(label: string, value: string, attention?: 'critical')}
	<div class="flex flex-wrap gap-x-4 gap-y-0.5 py-1 text-sm">
		<dt class="w-44 shrink-0 text-muted-text">{label}</dt>
		<dd class={['min-w-0 grow basis-48 wrap-anywhere', attention === 'critical' && 'text-critical']}>{value}</dd>
	</div>
{/snippet}

{#snippet dns(seen: Seen)}
	<Card title={m.domain_dns_title()}>
		{#if seen.dns.read === 'read'}
			<dl>
				{@render field(m.domain_change_ns(), list(seen.dns.ns))}
				{@render field(m.domain_change_ds(), list(seen.dns.ds))}
				{@render field(m.domain_change_validated(), dnssec(seen.dns), seen.dns.ds.length > 0 && !seen.dns.validated ? 'critical' : undefined)}
				{@render field(m.domain_change_caa(), list(seen.dns.caa))}
			</dl>
		{:else}
			<p class={muted}>{m.domain_dns_not_read({ why: seen.dns.why })}</p>
		{/if}
	</Card>
{/snippet}

{#snippet registry(seen: Seen)}
	<Card title={m.domain_registry_title()}>
		{#if seen.registry.read === 'read'}
			<dl>
				{@render field(m.domain_registry_source(), seen.registry.source)}
				{@render field(m.domain_registrar(), seen.registry.registrar ?? m.domain_not_named())}
				{@render field(m.domain_statuses(), seen.registry.statuses === null ? m.domain_statuses_unshown() : list(seen.registry.statuses))}
				{@render field(m.domain_delegation(), list(seen.registry.nameservers))}
				{#if seen.registry.expires !== null}{@render field(m.domain_expires(), when(seen.registry.expires))}{/if}
			</dl>
		{:else}
			<p class={muted}>{m.domain_registry_not_read({ why: seen.registry.why })}</p>
		{/if}
	</Card>
{/snippet}

{#snippet certify(seen: Seen)}
	<Card title={m.domain_certify_title()}>
		{#if seen.caa_governing === null}
			<p class={muted}>{m.domain_caa_unread()}</p>
		{:else if seen.caa_governing.at === null}
			<p class={muted}>{m.domain_caa_nothing()}</p>
		{:else}
			<p class="text-sm">{m.domain_caa_at({ at: seen.caa_governing.at })}</p>
			{#each seen.caa_governing.records as r (r)}<code class="mt-1 block {code}">{r}</code>{/each}
		{/if}
		{#if seen.accounts.length === 0}
			<p class="mt-3 {muted}">{m.domain_no_account()}</p>
		{:else}
			<ul class="mt-2">
				{#each seen.accounts as a (a.account.uri)}
					<Row>
						<p class="font-medium">{a.account.who}</p>
						<p class="text-xs text-muted-text wrap-anywhere">{a.account.uri}</p>
						{@const by = challenges(a.account)}
						{#if by}<p class="text-xs text-muted-text">{by}</p>{/if}
						{#snippet aside()}
							{#if a.verdict === null}
								<span class={muted}>{m.domain_verdict_unknown()}</span>
							{:else}
								<Mark attention={a.verdict === 'refused' ? 'critical' : a.verdict === 'pinned' ? 'ok' : 'notice'} label={caaVerdict[a.verdict]()} />
							{/if}
						{/snippet}
					</Row>
				{/each}
			</ul>
		{/if}
	</Card>
{/snippet}

{#snippet advice(seen: Seen)}
	<Card title={m.domain_advice_title()}>
		{#if seen.advice.length === 0}
			<p class={muted}>{m.domain_advice_none()}</p>
		{:else}
			<ul>
				{#each seen.advice as a (a.kind)}
					<Row>
						<p class="text-sm">{domainAdvice(a)}</p>
						{#if a.kind === 'pin'}
							{#each a.records as r (r.record)}
								<p class="mt-2 text-xs text-muted-text">{r.wildcard ? m.domain_pin_wildcard({ who: r.who }) : r.who}</p>
								<code class="mt-1 block {code}">{r.record}</code>
							{/each}
						{/if}
					</Row>
				{/each}
			</ul>
		{/if}
	</Card>
{/snippet}

{#snippet logs(watch: Schemas['CtWatch'])}
	<Card title={m.domain_logs_title()}>
		{#if watch.watch === 'unread'}
			<p class={muted}>{m.domain_logs_unread({ why: watch.why })}</p>
		{:else if watch.watch === 'not_started'}
			<p class={muted}>{m.domain_logs_not_started()}</p>
		{:else if watch.foreign.length === 0}
			<p class={muted}>{m.domain_logs_clean()}</p>
		{:else}
			<p class="mb-2 text-sm text-critical">{m.domain_logs_foreign()}</p>
			<ul>
				{#each watch.foreign as i (i.id)}
					<Row>
						<p class="font-mono text-sm wrap-anywhere">{i.names.join(', ')}</p>
						<p class="text-xs text-muted-text">{m.domain_issuance({ issuer: i.issuer, day: when(i.not_before), id: i.id })}</p>
						{#snippet aside()}<Mark attention="critical" />{/snippet}
					</Row>
				{/each}
			</ul>
		{/if}
	</Card>
{/snippet}

<div class="flex max-w-4xl flex-col gap-4">
	<p class={muted}>{m.domain_explanation()}</p>
	<Loaded resource={domain}>
		{#snippet children(view)}
			{#if view.scope === 'no_exposure'}
				<p class="text-sm">{m.domain_no_exposure()}</p>
			{:else if view.scope === 'internal'}
				<p class="text-sm">{m.domain_internal({ domain: view.domain })}</p>
			{:else}
				<p class="text-sm">
					<span class="font-mono font-medium">{m.domain_zone({ zone: view.zone })}</span>
					{#if view.reading !== null}<span class="text-muted-text"> — {m.domain_read_at({ when: when(view.reading.read_at) })}</span>{/if}
				</p>
				{#if view.reading === null}
					<p class={muted}>{m.domain_never_read()}</p>
				{:else if view.reading.stale}
					<p class="text-sm text-attention">{m.domain_stale()}</p>
				{/if}

				{#if view.drifts.length > 0}
					<Card title={m.domain_moved_title()}>
						<p class="mb-2 text-sm font-medium text-critical">{m.domain_moved_explanation()}</p>
						<ul>
							{#each view.drifts as d (d.what)}
								<Row>
									<p class="font-medium">{domainChange[d.what]()}</p>
									<p class="text-sm wrap-anywhere">{m.domain_drift({ was: driftSide(d.was, d.what), now: driftSide(d.now, d.what) })}</p>
									{#snippet aside()}<Mark attention="critical" />{/snippet}
								</Row>
							{/each}
						</ul>
					</Card>
				{/if}

				<Card title={m.domain_baseline_title()}>
					{#if view.baseline_at === null}
						<p class="text-sm text-attention">{m.domain_baseline_none()}</p>
					{:else}
						<p class="text-sm">{m.domain_baseline_at({ when: when(view.baseline_at) })}</p>
					{/if}
					<p class="mt-2 {muted}">{m.domain_accept_explanation()}</p>
					<div class="mt-3 flex flex-wrap items-center gap-2">
						<code class="min-w-0 grow basis-48 {code}">{accept}</code>
						<button type="button" class={button} onclick={(e) => copy(e.currentTarget)}
							>{copied === undefined ? m.action_copy() : copied === 'copied' ? m.action_copied() : m.action_copy_selected()}</button
						>
					</div>
				</Card>

				{@render logs(view.logs)}
				{#if view.reading !== null}
					{@render advice(view.reading)}
					{@render certify(view.reading)}
					<div class="grid gap-4 lg:grid-cols-2">
						{@render dns(view.reading)}
						{@render registry(view.reading)}
					</div>
				{/if}
			{/if}
		{/snippet}
	</Loaded>
</div>
