import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { Schemas } from './api/client';
import { chosen, paint, variable } from './theme';

type Theme = Schemas['Theme'];

/** The palette roles, as the controller's document declares them. */
const roles: string[] = JSON.parse(readFileSync('openapi.json', 'utf8')).components.schemas.Colours
	.required;

function theme(name: string, shipped = true): Theme {
	return {
		name,
		shipped,
		base: 'dark',
		scale: null,
		typeface_url: null,
		typeface_mono_url: null,
		colours: Object.fromEntries(roles.map((r, i) => [r, `value-${i}`])) as Theme['colours']
	};
}

/** Enough of an element for `paint`: what it set, readable afterwards. */
function element() {
	const set = new Map<string, string>();
	const style = {
		colorScheme: '',
		fontSize: '',
		setProperty: (k: string, v: string) => void set.set(k, v)
	};
	return { set, root: { style } as unknown as HTMLElement, style };
}

describe('the palette', () => {
	it('declares in app.css exactly the roles the controller serves', () => {
		// 🔴 A role the server adds and the stylesheet does not declare has no utility —
		// `text-new-role` produces nothing, silently; one the stylesheet keeps after the
		// server dropped it paints the system colour forever. Read from both ends.
		const css = readFileSync('src/app.css', 'utf8');
		const declared = [...css.matchAll(/^\s*(--color-[a-z-]+):/gm)].map((x) => x[1]).sort();
		expect(roles.length).toBe(12);
		expect(declared).toEqual(roles.map(variable).sort());
	});

	it('is painted, every role, from the theme', () => {
		const { set, root, style } = element();
		paint({ ...theme('Light'), base: 'light', scale: 1.25 }, root);
		expect([...set.keys()].sort()).toEqual(roles.map(variable).sort());
		expect(set.get('--color-muted-text')).toBe(`value-${roles.indexOf('muted_text')}`);
		expect(style.colorScheme).toBe('light');
		expect(style.fontSize).toBe('125%');
	});
});

describe('the theme painted', () => {
	const served = [theme('Dark'), theme('Light'), theme('Maison', false)];

	it('is the person’s, else the installation’s, else the first served', () => {
		expect(chosen(served, 'Maison', 'Light')?.name).toBe('Maison');
		expect(chosen(served, null, 'Light')?.name).toBe('Light');
		expect(chosen(served, undefined, null)?.name).toBe('Dark');
	});

	it('survives a chosen theme that is no longer served', () => {
		// A declared theme removed from its file after someone picked it: they still get a
		// painted screen, not an unthemed one.
		expect(chosen(served, 'Gone', null)?.name).toBe('Dark');
		expect(chosen([], 'Gone', null)).toBeUndefined();
	});
});
