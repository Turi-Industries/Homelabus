import { covers, title, where, type Issue } from '#lib/causes.ts';
import { modules } from '#lib/modules/index.ts';
import type { Module } from '#lib/modules/module.ts';

/**
 * An inbox line: one issue the controller grouped by cause, worded, and filed under
 * the module that answers for the cause.
 */
export interface Line {
	issue: Issue;
	attention: Exclude<Issue['attention'], 'ok'>;
	module: Module | undefined;
	title: string;
	detail: string | null;
	href: string;
	/** Set aside by this person until then, in seconds; `null` while it is in view. */
	aside: number | null;
}

/** The modules by the causes they declare: `modules.test.ts` holds each to one. */
function owner(kind: Issue['cause']['kind']): Module | undefined {
	return modules.find((x) => x.causes?.includes(kind));
}

/**
 * The lines, in the server's order — critical first. The grouping is the server's:
 * forty-eight half-created accounts are two lines because the CONTROLLER says they are
 * two causes, and every client agrees.
 */
export function lines(issues: Issue[]): Line[] {
	return issues.flatMap((issue) =>
		issue.attention === 'ok'
			? []
			: [
					{
						issue,
						attention: issue.attention,
						module: owner(issue.cause.kind),
						title: title(issue),
						detail: covers(issue),
						href: where(issue),
						aside: issue.aside_until
					}
				]
	);
}

/**
 * What a module's navigation entry counts: the causes it answers for, not their
 * subjects — and not what this person set aside, which is listed apart and counted there.
 */
export function concerning(all: Line[], module: Module): { count: number; critical: boolean } {
	const own = all.filter((l) => l.module === module && l.aside === null);
	return { count: own.length, critical: own.some((l) => l.attention === 'critical') };
}
