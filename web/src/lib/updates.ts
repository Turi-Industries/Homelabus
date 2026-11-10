import type { Schemas } from '#lib/api/client.ts';
import { m } from '#lib/paraglide/messages.js';

export type WaitingUpdate = Schemas['WaitingUpdate'];
type Why = Schemas['UpdateWhy'];
type Refusal = Schemas['UpdateRefusal'];

/**
 * What an update moves, in this language. The server decided it; this only says it, and
 * a `switch` ending on `never` keeps a kind the controller adds from compiling unsaid.
 */
export function moves(u: WaitingUpdate): string {
	switch (u.moves) {
		case 'version':
		case 'catalog':
			return m.updates_moves_to({ from: u.from_tag, to: u.to_tag ?? u.from_tag });
		case 'rebuild':
			return m.updates_moves_rebuild({ tag: u.from_tag });
		case 'companions':
			return m.updates_moves_companions({ tag: u.from_tag });
	}
	const _: never = u.moves;
	return _;
}

/** Who applies it. */
export function who(u: WaitingUpdate): string {
	switch (u.who) {
		case 'automatic':
			return m.updates_who_automatic();
		case 'one_click':
			return m.updates_who_one_click();
		case 'manual':
			return m.updates_who_manual({ app: u.app });
	}
	const _: never = u.who;
	return _;
}

const jumps: Record<Schemas['UpdateJump'], () => string> = {
	patch: m.updates_jump_patch,
	minor: m.updates_jump_minor,
	major: m.updates_jump_major
};

const reaches: Record<Schemas['UpdateReach'], () => string> = {
	none: m.updates_reach_none,
	patch: m.updates_reach_patch,
	minor: m.updates_reach_minor
};

/** Why a person is needed. */
export function why(w: Why): string {
	switch (w.kind) {
		case 'major':
			return m.updates_why_major();
		case 'beyond_reach':
			return (w.by_house ? m.updates_why_beyond_house : m.updates_why_beyond_manifest)({
				jump: jumps[w.jump](),
				reach: reaches[w.reach]()
			});
		case 'notes_say':
			return m.updates_why_notes_say({ tag: w.tag, word: w.word });
		case 'notes_missing':
			return m.updates_why_notes_missing({ tag: w.tag });
		case 'notes_unreadable':
			return m.updates_why_notes_unreadable();
	}
	const _: never = w;
	return _;
}

/** What the automatic path, or an approval, ran into. The tool's own text, shown as received. */
export function refused(r: Refusal): { said: string; detail: string | null } {
	switch (r.kind) {
		case 'vulnerable':
			return { said: m.updates_refused_vulnerable(), detail: r.described };
		case 'copy_failed':
			return { said: m.updates_refused_copy_failed(), detail: r.error };
		case 'failed':
			return { said: m.updates_refused_failed(), detail: r.error };
		case 'rolled_back':
			return { said: m.updates_refused_rolled_back(), detail: r.reason };
		case 'paused':
			return { said: m.updates_refused_paused(), detail: null };
		case 'inconclusive':
			return { said: m.updates_refused_inconclusive(), detail: null };
		case 'undone':
			return { said: m.updates_refused_undone(), detail: null };
	}
	const _: never = r;
	return _;
}
