import { describe, expect, it } from 'vitest';
import { parse, view, write, type Column, type Filter } from './listing';

type Person = { name: string; age: number | null; role: string };
const people: Person[] = [
	{ name: 'Léna', age: 41, role: 'admin' },
	{ name: 'camille', age: null, role: 'user' },
	{ name: 'dominique', age: 30, role: 'user' },
	{ name: 'sacha', age: 22, role: 'guest' }
];
const columns: Column<Person>[] = [
	{ id: 'name', label: () => 'name', value: (p) => p.name },
	{ id: 'age', label: () => 'age', value: (p) => p.age, numeric: true }
];
const role: Filter<Person> = {
	id: 'role',
	label: () => 'role',
	options: [],
	test: (p, v) => p.role === v
};
const state = (query: string) => parse(new URLSearchParams(query), [role]);

describe('a listing', () => {
	it('finds a name typed without its accent', () => {
		expect(view(people, columns, [role], state('q=lena')).shown.map((p) => p.name)).toEqual(['Léna']);
	});

	it('keeps the server order until a column is chosen', () => {
		expect(view(people, columns, [], state('')).shown).toEqual(people);
	});

	it('sorts an unknown last, whichever the direction', () => {
		expect(view(people, columns, [], state('sort=age')).shown.map((p) => p.age)).toEqual([22, 30, 41, null]);
		expect(view(people, columns, [], state('sort=age&dir=desc')).shown.map((p) => p.age)).toEqual([41, 30, 22, null]);
	});

	it('filters, and counts what it kept before cutting the page', () => {
		const v = view(people, columns, [role], state('role=user'), 1);
		expect(v.matched).toBe(2);
		expect(v.pages).toBe(2);
		expect(v.shown.map((p) => p.name)).toEqual(['camille']);
	});

	it('never shows a page past the last', () => {
		expect(view(people, columns, [], state('page=9'), 3).page).toBe(2);
	});

	it('leaves the defaults out of the URL, and reads back what it wrote', () => {
		const url = new URL('http://x/accounts?other=1');
		const written = write(url, { q: 'lena', sort: 'age', desc: true, page: 1, filters: { role: 'user' } }, [role]);
		expect(written).toBe('/accounts?other=1&q=lena&sort=age&dir=desc&role=user');
		expect(parse(new URL(written, 'http://x').searchParams, [role])).toEqual({
			q: 'lena',
			sort: 'age',
			desc: true,
			page: 1,
			filters: { role: 'user' }
		});
	});
});
