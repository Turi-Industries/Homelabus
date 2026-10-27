import { describe, expect, it } from 'vitest';
import { bands, columns, pack, type Placed, type Size } from './layout.ts';

/** The cells no tile covers, and the cells two tiles cover. */
function holes(placed: Placed[], cols: number, rows: number): { empty: string[]; twice: string[] } {
	const count: number[][] = Array.from({ length: rows }, () => Array(cols).fill(0));
	for (const p of placed) {
		for (let y = p.y; y < p.y + p.h; y++) {
			const row = count[y] as number[];
			for (let x = p.x; x < p.x + p.w; x++) row[x] = (row[x] ?? 0) + 1;
		}
	}
	const cells = count.flatMap((row, y) => row.map((n, x) => ({ n, at: `${x},${y}` })));
	return { empty: cells.filter((c) => c.n === 0).map((c) => c.at), twice: cells.filter((c) => c.n > 1).map((c) => c.at) };
}

/** The share of random layouts that end in bands, at most: none of 5,000 on 2026-10-10. */
const BANDED = 0.01;

/** A reproducible sequence: a failure is a seed someone can replay. */
function random(seed: number) {
	return () => {
		seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
		return seed / 2_147_483_648;
	};
}

describe('the home', () => {
	it('lays the default out exactly, with nothing to grow', () => {
		const sizes = [
			{ w: 4, h: 1 },
			{ w: 2, h: 2 },
			{ w: 1, h: 1 },
			{ w: 1, h: 1 },
			{ w: 1, h: 1 },
			{ w: 1, h: 1 }
		];
		const { placed, rows } = pack(sizes, 4);
		expect(rows).toBe(3);
		expect(placed).toEqual([
			{ x: 0, y: 0, w: 4, h: 1 },
			{ x: 0, y: 1, w: 2, h: 2 },
			{ x: 2, y: 1, w: 1, h: 1 },
			{ x: 3, y: 1, w: 1, h: 1 },
			{ x: 2, y: 2, w: 1, h: 1 },
			{ x: 3, y: 2, w: 1, h: 1 }
		]);
	});

	it('leaves no cell empty and covers none twice, whatever is asked', () => {
		// 🔴 A gap on the home reads as a card that failed to load. Twenty thousand
		// layouts of one to twelve tiles, every size a person can choose, every width.
		const next = random(7);
		const failures: string[] = [];
		for (let run = 0; run < 20_000; run++) {
			const sizes: Size[] = Array.from({ length: 1 + Math.floor(next() * 12) }, () => ({
				w: 1 + Math.floor(next() * 4),
				h: 1 + Math.floor(next() * 3)
			}));
			for (const cols of [1, 2, 3, 4]) {
				const { placed, rows } = pack(sizes, cols);
				const { empty, twice } = holes(placed, cols, rows);
				if (empty.length > 0 || twice.length > 0) failures.push(`${JSON.stringify(sizes)} on ${cols}: empty ${empty} twice ${twice}`);
			}
		}
		expect(failures.slice(0, 5)).toEqual([]);
	});

	it('falls back to bands rarely, and bands leave no hole either', () => {
		// The bands are the guarantee, not the layout: a tile no longer tucks in beside a
		// taller one. Raise the share only after looking at why it rose.
		const next = random(11);
		let banded = 0;
		const runs = 5_000;
		for (let run = 0; run < runs; run++) {
			const sizes: Size[] = Array.from({ length: 1 + Math.floor(next() * 12) }, () => ({
				w: 1 + Math.floor(next() * 4),
				h: 1 + Math.floor(next() * 3)
			}));
			const b = bands(sizes, 4);
			expect(holes(b.placed, 4, b.rows)).toEqual({ empty: [], twice: [] });
			if (pack(sizes, 4).banded) banded++;
		}
		expect(banded / runs).toBeLessThan(BANDED);
	});

	it('keeps the order asked: the first tile is at the top left', () => {
		const { placed } = pack([{ w: 1, h: 3 }, { w: 3, h: 1 }], 4);
		expect(placed[0]).toMatchObject({ x: 0, y: 0 });
	});

	it('narrows a tile to the columns there are, never past them', () => {
		const { placed } = pack([{ w: 4, h: 1 }], 2);
		expect(placed[0]).toEqual({ x: 0, y: 0, w: 2, h: 1 });
		expect(columns(328)).toBe(1);
		expect(columns(480)).toBe(2);
		expect(columns(704)).toBe(3);
		expect(columns(960)).toBe(4);
	});
});
