import { readFileSync } from 'node:fs';

const catalogue = JSON.parse(readFileSync('messages/en.json', 'utf8')) as Record<string, unknown>;

function escape(text: string): string {
	return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * What the interface says for a message, as a pattern: its inputs match anything. Read
 * from the catalogue, so rewording a message does not break the test that looks for it.
 */
export function said(key: string): RegExp {
	const text = catalogue[key];
	if (typeof text !== 'string') throw new Error(`no plain message ${key} in messages/en.json`);
	return new RegExp(text.split(/\{[^}]+\}/).map(escape).join('.+'));
}
