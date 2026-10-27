<script lang="ts">
	import { limits } from '#lib/api/limits.ts';
	import { api, type Schemas } from '#lib/api/client.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { refusal } from '#lib/resource.svelte.ts';
	import Qr from '#lib/ui/Qr.svelte';
	import Source from '#lib/ui/Source.svelte';
	import { input, muted, primary } from '#lib/ui/styles.ts';

	/**
	 * Sign-up, for someone with no account: no navigation, no session header — "Home"
	 * would send them to a refusal, and the identity of whoever opened the link would
	 * be someone else's.
	 *
	 * 🔴 The invitation travels in the fragment, which never reaches a server log; it is
	 * read once and erased from the address bar, so a copied URL does not carry it.
	 */
	const invitation = new URLSearchParams(location.hash.slice(1)).get('invitation');
	if (invitation !== null) history.replaceState(null, '', location.pathname);

	type Registered = Schemas['Registered'];
	let name = $state('');
	let displayName = $state('');
	let checked = $state<string | null>(null);
	let busy = $state(false);
	let problem = $state<string | undefined>();
	let done = $state<Registered | undefined>();

	async function send(apply: boolean) {
		if (invitation === null) return;
		busy = true;
		let answer;
		try {
			answer = await api.POST('/api/signup', {
				params: { query: { apply } },
				body: { invitation, name: name.trim(), display_name: displayName.trim() === '' ? null : displayName.trim() }
			});
		} catch (e) {
			// The network, not a refusal: said, and the button given back. The invitation
			// stays in this page to try again — erased from the address bar, a reload loses it.
			problem = m.state_never_received({ error: e instanceof Error ? e.message : String(e) });
			return;
		} finally {
			busy = false;
		}
		const { data, error, response } = answer;
		// The name is checked first, so a typo is refused before the link is spent.
		const result = (data ?? (typeof error === 'object' && error !== null && 'blockers' in error ? error : undefined)) as Registered | undefined;
		if (result === undefined) {
			problem = refusal(error, response);
		} else if (result.blockers.length > 0) {
			problem = m.signup_refused({ reasons: result.blockers.join(' · ') });
			checked = null;
		} else if (!apply) {
			problem = undefined;
			checked = name.trim();
		} else {
			done = result;
		}
	}
</script>

<svelte:head><title>{m.signup_title()}</title></svelte:head>

<main class="mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center gap-5 px-4 py-8">
	<h1 class="text-2xl font-semibold">{m.signup_title()}</h1>
	{#if invitation === null && done === undefined}
		<p class="font-medium">{m.signup_no_invitation()}</p>
		<p class={muted}>{m.signup_no_invitation_explanation()}</p>
	{:else if done !== undefined}
		{#if done.enrolment_link !== null}
			<p class="font-medium">{m.signup_finish_now()}</p>
			<p class={muted}>{m.signup_finish_now_explanation()}</p>
			<a href={done.enrolment_link} class={[primary, 'self-start']}>{m.signup_to_finish()}</a>
			<Qr value={done.enrolment_link} label={m.signup_finish_now()} />
		{:else}
			<p class="text-attention">{m.signup_incomplete_explanation()}</p>
		{/if}
		<a href="/" class="text-sm text-accent hover:underline">{m.signup_go_to_home_page()}</a>
	{:else}
		<p class={muted}>{m.signup_name_explanation()}</p>
		<form class="flex flex-col gap-3" onsubmit={(e) => (e.preventDefault(), void send(checked === name.trim()))}>
			<label class="flex flex-col gap-1 text-sm">{m.signup_name_label()}
				<input bind:value={name} maxlength={limits.SignupRequest.name.maxLength} placeholder={m.signup_first_name_hint()} autocomplete="username" autocapitalize="none" spellcheck="false" class={input} />
			</label>
			<p class="text-xs text-muted-text">{m.signup_name_rules()}</p>
			<label class="flex flex-col gap-1 text-sm">{m.signup_display_name()}
				<input bind:value={displayName} maxlength={limits.SignupRequest.display_name.maxLength} autocomplete="name" class={input} />
			</label>
			{#if checked !== null && checked === name.trim()}<p class="text-sm text-ok">{m.signup_name_available()}</p>{/if}
			{#if problem}<p role="alert" class="text-sm text-critical">{problem}</p>{/if}
			<button type="submit" class={[primary, 'self-start']} disabled={busy || name.trim() === ''}>
				{busy ? m.signup_creating() : checked === name.trim() ? m.signup_create_my_account() : m.signup_check_this_name()}
			</button>
		</form>
	{/if}
	<Source />
</main>
