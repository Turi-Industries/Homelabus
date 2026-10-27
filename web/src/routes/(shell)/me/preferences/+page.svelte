<script lang="ts">
	import { api } from '#lib/api/client.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { getLocale, locales, setLocale } from '#lib/paraglide/runtime.js';
	import { read, refusal } from '#lib/resource.svelte.ts';
	import { chosen, paint } from '#lib/theme.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { input, muted } from '#lib/ui/styles.ts';

	const preferences = read('/api/preferences');
	const themes = read('/api/themes');
	$effect(() => themes.watch());
	let failure = $state<string | undefined>();
	const languages: Record<string, () => string> = { en: m.me_language_en, fr: m.me_language_fr };

	async function choose(theme: string | null) {
		const { error, response } = await api.PUT('/api/preferences/theme', { body: { theme } });
		failure = response.ok ? undefined : m.me_theme_saved_failed({ error: refusal(error, response) });
		await preferences.refresh();
		const painted = themes.data && chosen(themes.data, preferences.data?.theme, preferences.data?.default);
		if (painted) paint(painted, document.documentElement);
	}

	async function setDensity(density: 'comfortable' | 'compact') {
		const { error, response } = await api.PUT('/api/preferences/density', { body: { density } });
		failure = response.ok ? undefined : m.me_density_saved_failed({ error: refusal(error, response) });
		if (response.ok) document.documentElement.dataset.density = density;
		await preferences.refresh();
	}
	const densities = { comfortable: m.settings_density_comfortable, compact: m.settings_density_compact };
</script>

<div class="grid gap-4 lg:grid-cols-2">
	<Card title={m.settings_your_theme()}>
		<p class="mb-3 {muted}">{m.settings_theme_follows_you()}</p>
		<Loaded resource={preferences}>
			{#snippet children(p)}
				<div class="flex flex-col gap-2">
					<label class="flex items-center gap-2 text-sm">
						<input type="radio" name="theme" checked={p.theme === null} onchange={() => choose(null)} />
						{p.default === null ? m.settings_installations_own() : m.settings_installations_own_with_name({ default: p.default })}
					</label>
					{#each p.available as name (name)}
						{@const theme = themes.data?.find((t) => t.name === name)}
						<label class="flex items-center gap-2 text-sm">
							<input type="radio" name="theme" checked={p.theme === name} onchange={() => choose(name)} />
							<span class="flex-1">{name}</span>
							{#if theme}
								<span class="flex overflow-hidden rounded border border-border">
									{#each ['background', 'surface', 'accent', 'ok', 'attention', 'critical'] as const as role (role)}
										<span class="size-4" style:background-color={theme.colours[role]}></span>
									{/each}
								</span>
							{/if}
						</label>
					{/each}
					{#if failure}<p role="alert" class="text-sm text-critical">{failure}</p>{/if}
				</div>
			{/snippet}
		</Loaded>
	</Card>
	<Card title={m.settings_density()}>
		<p class="mb-3 {muted}">{m.settings_density_explanation()}</p>
		<Loaded resource={preferences}>
			{#snippet children(p)}
				<div class="flex flex-col gap-2">
					{#each ['comfortable', 'compact'] as const as d (d)}
						<label class="flex items-center gap-2 text-sm">
							<input type="radio" name="density" checked={p.density === d} onchange={() => setDensity(d)} />
							{densities[d]()}
						</label>
					{/each}
				</div>
			{/snippet}
		</Loaded>
	</Card>
	<Card title={m.settings_language()}>
		<p class="mb-3 {muted}">{m.settings_language_explanation()}</p>
		<select value={getLocale()} aria-label={m.settings_language()} onchange={(e) => setLocale(e.currentTarget.value as (typeof locales)[number])} class={input}>
			{#each locales as l (l)}<option value={l}>{languages[l]?.() ?? l}</option>{/each}
		</select>
	</Card>
</div>
