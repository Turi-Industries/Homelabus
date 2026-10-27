import { afterEach, describe, expect, it, vi } from 'vitest';
import { copy } from './clipboard.ts';

describe('a copy button', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('falls back to selecting when the page has no clipboard, as over plain HTTP', async () => {
		vi.stubGlobal('navigator', {});
		await expect(copy('hlb storage init --apply', null)).resolves.toBe('selected');
	});

	it('falls back to selecting when the browser refuses the write', async () => {
		vi.stubGlobal('navigator', { clipboard: { writeText: () => Promise.reject(new Error('denied')) } });
		await expect(copy('hlb storage init --apply', null)).resolves.toBe('selected');
	});

	it('says it copied only when the clipboard took the text', async () => {
		const written: string[] = [];
		vi.stubGlobal('navigator', { clipboard: { writeText: async (t: string) => void written.push(t) } });
		await expect(copy('hlb storage init --apply', null)).resolves.toBe('copied');
		expect(written).toEqual(['hlb storage init --apply']);
	});
});
