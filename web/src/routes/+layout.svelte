<script lang="ts">
	import '../app.css';
	import { goto } from '$app/navigation';
	import type { Snippet } from 'svelte';
	import { api } from '#lib/api/client.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { getLocale } from '#lib/paraglide/runtime.js';
	import { chosen, paint, typefaces } from '#lib/theme.ts';

	let { children }: { children: Snippet } = $props();

	type Shell = { state: 'connecting' } | { state: 'painted' } | { state: 'failed'; error: string };
	let shell = $state<Shell>({ state: 'connecting' });

	async function start() {
		// Invitation links issued before sign-up had its own path pointed at `/`.
		if (location.pathname === '/' && location.hash.startsWith('#invitation=')) {
			void goto('/signup' + location.hash, { replaceState: true });
		}
		const root = document.documentElement;
		root.lang = getLocale();
		try {
			// Public, all three: the sign-in and sign-up screens are painted in the house's
			// colours too. Preferences answer 401 to someone signed out, who then gets the
			// installation's theme.
			const [themes, brand, preferences] = await Promise.all([
				api.GET('/api/themes'),
				api.GET('/api/appearance'),
				api.GET('/api/preferences')
			]);
			const theme =
				themes.data &&
				chosen(themes.data, preferences.data?.theme, brand.data?.default_theme);
			if (!theme) {
				shell = { state: 'failed', error: themes.error?.error ?? `${themes.response.status}` };
				retry();
				return;
			}
			paint(theme, root);
			root.dataset.density = preferences.data?.density ?? 'comfortable';
			shell = { state: 'painted' };
			// After the palette: a typeface that fails to load leaves the default letters,
			// never an unpainted screen.
			await typefaces(theme, root).catch(() => undefined);
		} catch (e) {
			shell = { state: 'failed', error: e instanceof Error ? e.message : String(e) };
			retry();
		}
	}

	// A controller that was restarting, or a budget spent by a burst of reloads, is a
	// moment, not a verdict: asked again until it answers, the failure stays on screen
	// meanwhile.
	function retry() {
		setTimeout(() => void start(), 5_000);
	}

	start();
</script>

{#if shell.state === 'painted'}
	{@render children()}
{:else if shell.state === 'connecting'}
	<p class="p-4 text-muted-text" aria-busy="true">{m.freshness_connecting()}</p>
{:else}
	<p class="p-4" role="alert">{m.freshness_cannot_connect({ error: shell.error })}</p>
{/if}
