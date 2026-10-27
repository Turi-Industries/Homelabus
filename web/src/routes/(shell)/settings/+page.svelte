<script lang="ts">
	import { limits } from '#lib/api/limits.ts';
	import { api, type Schemas } from '#lib/api/client.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { read, refusal } from '#lib/resource.svelte.ts';
	import Card from '#lib/ui/Card.svelte';
	import Loaded from '#lib/ui/Loaded.svelte';
	import { chosen } from '#lib/theme.ts';
	import { button, code, input, muted, primary } from '#lib/ui/styles.ts';

	const brand = read('/api/appearance');
	const themes = read('/api/themes');
	$effect(() => themes.watch());

	// A copy to edit: the resource keeps refreshing underneath, and a form that
	// followed it would undo what the person is typing.
	let draft = $state<Schemas['Brand'] | undefined>();
	let note = $state<{ ok: boolean; text: string } | undefined>();
	$effect(() => {
		if (draft === undefined && brand.data !== undefined) draft = { ...brand.data };
	});

	const hex = (rgb: number[] | null) =>
		rgb === null ? '' : '#' + rgb.map((c) => c.toString(16).padStart(2, '0')).join('');
	const channels = (value: string) => [1, 3, 5].map((i) => parseInt(value.slice(i, i + 2), 16));
	// With no brand accent a colour input shows black, which nothing on screen is. Each
	// theme then keeps its own; the one shown is the installation's theme's, as served —
	// only while no accent is SAVED, since the served colours carry the saved one.
	const own = $derived(
		brand.data?.accent === null && themes.data !== undefined
			? chosen(themes.data, null, draft?.default_theme)?.colours.accent
			: undefined
	);

	async function save() {
		if (draft === undefined) return;
		const { error, response } = await api.PUT('/api/appearance', { body: draft });
		note = response.ok ? { ok: true, text: m.settings_saved() } : { ok: false, text: m.settings_save_failed({ error: refusal(error, response) }) };
		await brand.refresh();
	}

	async function upload(file: File | null) {
		const { error, response } = await api.POST('/api/appearance/logo', {
			body: (file ?? new Blob()) as unknown as string,
			bodySerializer: (b: unknown) => b as BodyInit,
			headers: { 'content-type': file?.type || 'image/png' }
		});
		note = response.ok ? { ok: true, text: m.settings_saved() } : { ok: false, text: m.settings_save_failed({ error: refusal(error, response) }) };
		await brand.refresh();
	}
</script>

<div class="grid gap-4 lg:grid-cols-2">
	<Card title={m.settings_appearance()}>
		<p class="mb-3 {muted}">{m.settings_appearance_explanation()}</p>
		<Loaded resource={brand}>
			{#snippet children()}
				{#if draft !== undefined}
					<form class="flex flex-col gap-3" onsubmit={(e) => (e.preventDefault(), void save())}>
						<label class="flex flex-col gap-1 text-sm">{m.settings_brand_name()}<input bind:value={draft.name} maxlength={limits.Brand.name.maxLength} required class={input} /></label>
						<label class="flex flex-col gap-1 text-sm">{m.settings_footer()}
							<input value={draft.footer ?? ''} maxlength={limits.Brand.footer.maxLength} oninput={(e) => draft && (draft.footer = e.currentTarget.value || null)} class={input} />
						</label>
						<div class="flex flex-wrap items-center gap-3 text-sm">
							<label class="flex items-center gap-2">{m.settings_accent()}
								<input type="color" value={hex(draft.accent) || own} oninput={(e) => draft && (draft.accent = channels(e.currentTarget.value))} class="h-8 w-12 rounded border border-border bg-background" />
							</label>
							{#if draft.accent !== null}
								<button type="button" class={button} onclick={() => draft && (draft.accent = null)}>{m.settings_accent_theme()}</button>
							{:else}
								<span class={muted}>{m.settings_accent_theme()}</span>
							{/if}
						</div>
						<label class="flex flex-col gap-1 text-sm">{m.settings_default_theme()}
							<select value={draft.default_theme ?? ''} onchange={(e) => draft && (draft.default_theme = e.currentTarget.value || null)} class={input}>
								<option value="">{m.settings_installations_own()}</option>
								{#each themes.data ?? [] as t (t.name)}<option value={t.name}>{t.name}</option>{/each}
							</select>
						</label>
						<button type="submit" class={[primary, 'self-start']}>{m.settings_save()}</button>
						{#if note}<p role="status" class={['text-sm', note.ok ? 'text-ok' : 'text-critical']}>{note.text}</p>{/if}
					</form>
					<code class="mt-4 block {code}">{m.settings_appearance_command()}</code>
				{/if}
			{/snippet}
		</Loaded>
	</Card>

	<div class="flex flex-col gap-4">
		<Card title={m.settings_logo()}>
			<p class="mb-3 {muted}">{m.settings_logo_explanation()}</p>
			<div class="flex flex-wrap items-center gap-3">
				{#if brand.data?.logo}<img src="/api/appearance/logo?v={brand.received}" alt="" class="size-12 rounded" />{/if}
				<input type="file" accept="image/png,image/svg+xml" aria-label={m.settings_logo()} class="text-sm" onchange={(e) => upload(e.currentTarget.files?.[0] ?? null)} />
				{#if brand.data?.logo}<button type="button" class={button} onclick={() => upload(null)}>{m.settings_logo_remove()}</button>{/if}
			</div>
		</Card>

		<Card title={m.settings_legibility()}>
			<p class="mb-3 {muted}">{m.settings_legibility_explanation()}</p>
			<Loaded resource={themes}>
				{#snippet children(list)}
					<ul class="space-y-3">
						{#each list as t (t.name)}
							<li>
								<p class="mb-1 text-sm">{m.settings_theme_legible({ name: t.name })}</p>
								<div class="flex overflow-hidden rounded-md border border-border">
									{#each Object.entries(t.colours) as [role, colour] (role)}
										<span class="h-5 flex-1" style:background-color={colour} title={role}></span>
									{/each}
								</div>
							</li>
						{/each}
					</ul>
				{/snippet}
			</Loaded>
		</Card>
	</div>
</div>
