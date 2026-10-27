import type { Schemas } from './api/client';

type Theme = Schemas['Theme'];

/** The CSS variable a palette role is painted into: `muted_text` → `--color-muted-text`. */
export function variable(role: string): string {
	return `--color-${role.replaceAll('_', '-')}`;
}

/**
 * The theme to paint: the person's choice, else the installation's, else the first one
 * served — the controller lists the shipped themes first.
 *
 * ⚠️ A name that no longer matches a served theme falls through rather than failing:
 * the controller refuses an unknown name when it is CHOSEN, but a declared theme can be
 * removed from its file afterwards, and the person must still get a painted screen.
 */
export function chosen(
	themes: Theme[],
	person: string | null | undefined,
	installation: string | null | undefined
): Theme | undefined {
	return (
		themes.find((t) => t.name === person) ??
		themes.find((t) => t.name === installation) ??
		themes[0]
	);
}

/**
 * Overwrites the palette variables `app.css` declares with the theme's colours.
 *
 * Every colour comes from the server, already validated: the palette rule — no two
 * states indistinguishable under three colour-vision deficiencies, the text on the
 * accent picked for contrast — runs there, and repeating any of it here would be a
 * second copy to drift.
 */
export function paint(theme: Theme, root: HTMLElement): void {
	for (const [role, colour] of Object.entries(theme.colours)) {
		root.style.setProperty(variable(role), colour);
	}
	root.style.colorScheme = theme.base;
	root.style.fontSize = theme.scale === null ? '' : `${theme.scale * 100}%`;
}

/**
 * Loads the faces a theme names, and points Tailwind's font stacks at them. Without a
 * face, the stacks keep Tailwind's defaults. The URL is the one the theme carries.
 */
export async function typefaces(theme: Theme, root: HTMLElement): Promise<void> {
	const faces = [
		['--font-sans', 'hlb-proportional', theme.typeface_url, 'ui-sans-serif, system-ui, sans-serif'],
		['--font-mono', 'hlb-mono', theme.typeface_mono_url, 'ui-monospace, monospace']
	] as const;
	for (const [property, family, url, fallback] of faces) {
		if (url === null) {
			root.style.removeProperty(property);
			continue;
		}
		const face = new FontFace(family, `url(${JSON.stringify(url)})`);
		document.fonts.add(await face.load());
		root.style.setProperty(property, `${family}, ${fallback}`);
	}
}
