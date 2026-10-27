/** A tile's asked-for size, in cells of the grid. */
export interface Size {
	w: number;
	h: number;
}

/** Where a tile lands: its column and row (from 0), and the cells it covers. */
export interface Placed {
	x: number;
	y: number;
	w: number;
	h: number;
}

/**
 * How many columns the home has, at the width of the GRID in CSS pixels — not the
 * window's: beside the navigation, a 1280 px screen leaves the grid 960. A column is
 * never narrower than about 210 px, where a figure and its caption still fit.
 */
export function columns(width: number): number {
	if (width >= 840) return 4;
	if (width >= 630) return 3;
	if (width >= 420) return 2;
	return 1;
}

/**
 * The tiles laid out in order on a grid `cols` wide, with no cell empty: a home with a
 * hole in it reads as a card that failed to load.
 *
 * Each tile goes to the first place it fits, reading the grid line by line — so a small
 * tile fills a gap a larger one left before it. What is still empty is then closed by
 * growing a neighbour into it ({@link close}). The few layouts that leaves a hole in
 * are laid out in bands instead ({@link bands}), which cannot leave one.
 */
export function pack(sizes: Size[], cols: number): { placed: Placed[]; rows: number; banded: boolean } {
	const asked = sizes.map(({ w, h }) => ({ w: Math.min(Math.max(w, 1), cols), h: Math.max(h, 1) }));
	const placed = firstFit(asked, cols);
	const rows = placed.reduce((n, p) => Math.max(n, p.y + p.h), 0);
	if (close(placed, cols, rows)) return { placed, rows, banded: false };
	return { ...bands(asked, cols), banded: true };
}

function firstFit(sizes: Size[], cols: number): Placed[] {
	const placed: Placed[] = [];
	const free = (x: number, y: number, w: number, h: number) =>
		!placed.some((p) => x < p.x + p.w && p.x < x + w && y < p.y + p.h && p.y < y + h);
	for (const { w, h } of sizes) {
		for (let y = 0, done = false; !done; y++) {
			for (let x = 0; x + w <= cols && !done; x++) {
				if (free(x, y, w, h)) {
					placed.push({ x, y, w, h });
					done = true;
				}
			}
		}
	}
	return placed;
}

type Side = 'right' | 'down' | 'left' | 'up';

/**
 * Grows tiles into the empty cells of a `cols` × `rows` grid, in place, and says whether
 * none is left.
 *
 * A tile grows by one line along a whole edge, so it stays a rectangle. The line may be
 * empty, or held by tiles that start on it, lie within the edge and are more than one
 * line thick: those give the line up, and the boundary between the two moves. The tile
 * on the left of a hole is tried first, then the one above, on its right, below.
 */
function close(placed: Placed[], cols: number, rows: number): boolean {
	const owner = () => {
		const grid: number[][] = Array.from({ length: rows }, () => Array<number>(cols).fill(-1));
		placed.forEach((p, i) => {
			for (let y = p.y; y < p.y + p.h; y++) for (let x = p.x; x < p.x + p.w; x++) (grid[y] as number[])[x] = i;
		});
		return grid;
	};
	const sides: [Side, number, number][] = [
		['right', -1, 0],
		['down', 0, -1],
		['left', 1, 0],
		['up', 0, 1]
	];
	// Each growth fills at least one empty cell and empties none, so this ends.
	for (let grid = owner(); ; grid = owner()) {
		const holes = grid.flatMap((row, y) => row.flatMap((o, x) => (o === -1 ? [{ x, y }] : [])));
		if (holes.length === 0) return true;
		const grown = holes.some(({ x, y }) =>
			sides.some(([side, dx, dy]) => {
				const i = grid[y + dy]?.[x + dx] ?? -1;
				return i !== -1 && grow(placed, grid, i, side);
			})
		);
		if (!grown) return false;
	}
}

/** Grows `placed[i]` by one line on `side`, if the line can be had. */
function grow(placed: Placed[], grid: number[][], i: number, side: Side): boolean {
	const t = placed[i] as Placed;
	const across = side === 'right' || side === 'left';
	const line = side === 'right' ? t.x + t.w : side === 'left' ? t.x - 1 : side === 'down' ? t.y + t.h : t.y - 1;
	if (line < 0 || line >= (across ? (grid[0]?.length ?? 0) : grid.length)) return false;
	const span = across ? [t.y, t.y + t.h] : [t.x, t.x + t.w];
	// A growth that fills no empty cell only trades cells, and could trade them forever.
	if (!hasEmpty(grid, line, span, across)) return false;
	const givers = new Set<number>();
	for (let k = span[0] as number; k < (span[1] as number); k++) {
		const o = (across ? grid[k]?.[line] : grid[line]?.[k]) ?? -1;
		if (o === -1) continue;
		const u = placed[o] as Placed;
		// The giver starts on the line, lies within the edge, and keeps a line of its own.
		const starts = side === 'right' ? u.x === line : side === 'left' ? u.x + u.w - 1 === line : side === 'down' ? u.y === line : u.y + u.h - 1 === line;
		const within = across ? u.y >= (span[0] as number) && u.y + u.h <= (span[1] as number) : u.x >= (span[0] as number) && u.x + u.w <= (span[1] as number);
		const thick = across ? u.w > 1 : u.h > 1;
		if (!starts || !within || !thick) return false;
		givers.add(o);
	}
	for (const o of givers) {
		const u = placed[o] as Placed;
		if (side === 'right') (u.x += 1), (u.w -= 1);
		else if (side === 'left') u.w -= 1;
		else if (side === 'down') (u.y += 1), (u.h -= 1);
		else u.h -= 1;
	}
	if (side === 'right') t.w += 1;
	else if (side === 'left') (t.x -= 1), (t.w += 1);
	else if (side === 'down') t.h += 1;
	else (t.y -= 1), (t.h += 1);
	return true;
}

function hasEmpty(grid: number[][], line: number, span: number[], across: boolean): boolean {
	for (let k = span[0] as number; k < (span[1] as number); k++) {
		if (((across ? grid[k]?.[line] : grid[line]?.[k]) ?? -1) === -1) return true;
	}
	return false;
}

/**
 * The tiles in order, in bands as wide as the grid: a band is as tall as its tallest
 * tile, each tile in it as tall as the band, and its last tile as wide as what is left.
 * Coarser than packing — a small tile no longer tucks in beside a tall one — but it
 * cannot leave a hole.
 */
export function bands(sizes: Size[], cols: number): { placed: Placed[]; rows: number } {
	const placed: Placed[] = [];
	let band: Placed[] = [];
	let y = 0;
	const flush = () => {
		const last = band[band.length - 1];
		if (last === undefined) return;
		last.w = cols - last.x;
		const h = Math.max(...band.map((p) => p.h));
		for (const p of band) p.h = h;
		y += h;
		band = [];
	};
	for (const { w, h } of sizes) {
		const width = Math.min(Math.max(w, 1), cols);
		const x = band.reduce((n, p) => n + p.w, 0);
		if (x + width > cols) flush();
		const p = { x: band.reduce((n, q) => n + q.w, 0), y, w: width, h: Math.max(h, 1) };
		band.push(p);
		placed.push(p);
	}
	flush();
	return { placed, rows: y };
}
