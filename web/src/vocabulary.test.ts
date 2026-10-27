import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ALERT_RULES, ROLES, SAFEGUARDS } from '#lib/vocabulary.ts';

describe('the vocabulary offered in forms', () => {
	it('names every level hlb-types declares, and no other', () => {
		const source = readFileSync('../crates/hlb-types/src/rbac.rs', 'utf8');
		const body = source.match(/pub enum Role \{([\s\S]*?)\n\}/)?.[1] ?? '';
		// `rename_all = "lowercase"`: the wire name is the variant, lower-cased.
		const variants = [...body.matchAll(/^\s{4}([A-Z]\w*),?$/gm)].map((x) => x[1]?.toLowerCase());
		expect(variants.length).toBeGreaterThan(2);
		expect(Object.keys(ROLES).sort()).toEqual(variants.sort());
	});

	it('names every break-glass safeguard hlb-api declares, and no other', () => {
		const source = readFileSync('../crates/hlb-api/src/breakglass.rs', 'utf8');
		// An id is written in place, or names one of the file's constants.
		const consts = new Map([...source.matchAll(/^pub const ([A-Z_]+): &str = "([a-z-]+)";$/gm)].map((x) => [x[1], x[2]]));
		const ids = [...source.matchAll(/^\s+id: (?:"([a-z-]+)"|([A-Z_]+))\.into\(\),$/gm)].map((x) => x[1] ?? consts.get(x[2] ?? ''));
		expect(ids).not.toContain(undefined);
		expect(ids.length).toBeGreaterThan(5);
		expect(Object.keys(SAFEGUARDS).sort()).toEqual(ids.sort());
	});

	it('words every alert rule hlb-metrics evaluates, and no other', () => {
		const source = readFileSync('../crates/hlb-metrics/src/rules.rs', 'utf8');
		const body = source.match(/pub fn default_rules\(\)[\s\S]*?\n\}/)?.[0] ?? '';
		const names = [...body.matchAll(/name: "([a-z-]+)"/g)].map((x) => x[1]);
		expect(names.length).toBeGreaterThan(5);
		expect(Object.keys(ALERT_RULES).sort()).toEqual(names.sort());
	});
});
