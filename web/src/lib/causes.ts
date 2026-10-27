import type { Schemas } from '#lib/api/client.ts';
import { number } from '#lib/format.ts';
import { m } from '#lib/paraglide/messages.js';
import { SAFEGUARDS } from '#lib/vocabulary.ts';
import { topology } from '#lib/words.ts';

export type Issue = Schemas['Issue'];
export type Cause = Schemas['Cause'];
export type CauseKind = Cause['kind'];

/** What an issue is worded with: its count, as a number for the plural and as text. */
function counted(issue: Issue) {
	return { count: issue.subjects.length, shown: number(issue.subjects.length) };
}

/**
 * The line an issue reads as, in the person's language. The server decided the cause
 * and grouped it; this only says it. A `switch` ending on `never`: a cause the
 * controller adds does not compile here until it has words.
 */
export function title(issue: Issue): string {
	const c = issue.cause;
	const n = counted(issue);
	switch (c.kind) {
		case 'app_failed':
			return m.cause_app_failed(n);
		case 'app_partial':
			return m.cause_app_partial(n);
		case 'guide_blocking':
			return m.cause_guide_blocking(n);
		case 'guide_pending':
			return m.cause_guide_pending(n);
		case 'catalog_changed':
			return m.cause_catalog_changed(n);
		case 'job_failed':
			return m.cause_job_failed(n);
		case 'mail_waiting':
			return m.cause_mail_waiting(n);
		case 'never_backed_up':
			return m.cause_never_backed_up(n);
		case 'no_backup_destination':
			return m.cause_no_backup_destination();
		case 'no_fresh_copy':
			return m.cause_no_fresh_copy(n);
		case 'one_fresh_copy':
			return m.cause_one_fresh_copy(n);
		case 'single_destination':
			return m.cause_single_destination();
		case 'drill_never':
			return m.cause_drill_never();
		case 'drill_stale':
			return m.cause_drill_stale();
		case 'node_unreachable':
			return m.cause_node_unreachable(n);
		case 'node_disk_full':
			return m.cause_node_disk_full(n);
		case 'node_disk_filling':
			return m.cause_node_disk_filling(n);
		case 'node_swapping':
			return m.cause_node_swapping(n);
		case 'node_load':
			return m.cause_node_load(n);
		case 'node_reboot_pending':
			return m.cause_node_reboot_pending(n);
		case 'topology':
			return m.cause_topology({ verdict: topology(c.verdict) });
		case 'drift':
			return m.cause_drift(n);
		case 'deadman_absent':
			return m.cause_deadman_absent();
		case 'deadman_silent':
			return m.cause_deadman_silent();
		case 'exposure_unknown':
			return m.cause_exposure_unknown();
		case 'exposed_against_manifest':
			return m.cause_exposed_against_manifest(n);
		case 'not_published':
			return m.cause_not_published(n);
		case 'route_not_applied':
			return m.cause_route_not_applied(n);
		case 'orphan_route':
			return m.cause_orphan_route(n);
		case 'secret_never_rotated':
			return m.cause_secret_never_rotated(n);
		case 'secret_rotation_due':
			return m.cause_secret_rotation_due(n);
		case 'certificate_expiring':
			return m.cause_certificate_expiring(n);
		case 'admin_tokens':
			return m.cause_admin_tokens();
		case 'admin_unknown':
			return m.cause_admin_unknown();
		case 'audit_broken':
			return m.cause_audit_broken();
		case 'audit_unreadable':
			return m.cause_audit_unreadable();
		case 'assertion_broken':
			return m.cause_assertion_broken(n);
		case 'assertion_unknown':
			return m.cause_assertion_unknown(n);
		case 'mail_record_wrong':
			return m.cause_mail_record_wrong(n);
		case 'mail_record_unknown':
			return m.cause_mail_record_unknown(n);
		case 'mail_blocklists_refused':
			return m.cause_mail_blocklists_refused(n);
		case 'account_without_mailbox':
			return m.cause_account_without_mailbox(n);
		case 'account_without_identity':
			return m.cause_account_without_identity(n);
		case 'account_empty':
			return m.cause_account_empty(n);
		case 'alias_still_receiving':
			return m.cause_alias_still_receiving(n);
		case 'safeguard':
			return m.cause_safeguard(n);
		case 'alert':
			return c.evaluable ? m.cause_alert({ rule: c.rule }) : m.cause_alert_blind({ rule: c.rule });
	}
	const _: never = c;
	return _;
}

/** What it covers, by name: the first few, then how many more. */
export function covers(issue: Issue, few = 4): string | null {
	// A safeguard's subject is its stored id; a person reads its name.
	const names =
		issue.cause.kind === 'safeguard' ? issue.subjects.map((id) => SAFEGUARDS[id]?.() ?? id) : issue.subjects;
	if (names.length === 0) return null;
	if (names.length <= few) return names.join(', ');
	return m.cause_and_more({ names: names.slice(0, few).join(', '), more: number(names.length - few) });
}

/**
 * Where the line leads: the one thing, when it is about one, or the list that holds
 * them all — filtered to them when the list can be.
 */
export function where(issue: Issue): string {
	const c = issue.cause;
	const one = issue.subjects.length === 1 ? encodeURIComponent(issue.subjects[0] ?? '') : undefined;
	switch (c.kind) {
		case 'app_failed':
			return one ? `/apps/${one}` : '/apps?attention=critical';
		// A partial app is `notice`, or `critical` when its backups are late: no attention
		// filter holds them all, and `?attention=critical` hid most of them.
		case 'app_partial':
			return one ? `/apps/${one}` : '/apps';
		case 'catalog_changed':
		case 'job_failed':
		case 'assertion_broken':
		case 'assertion_unknown':
			return one ? `/apps/${one}` : '/apps';
		// No page lists the records or the queue, whose subjects are names and domains,
		// not apps: Stalwart's is where its mail is, and the CLI says the rest —
		// `hlb mail dns`, `hlb mail queue`.
		case 'mail_record_wrong':
		case 'mail_record_unknown':
		case 'mail_blocklists_refused':
		case 'mail_waiting':
			return '/apps/stalwart';
		case 'guide_blocking':
		case 'guide_pending':
			return '/todo';
		case 'never_backed_up':
		case 'no_fresh_copy':
		case 'one_fresh_copy':
			return one ? `/apps/${one}/backups` : '/backups';
		case 'no_backup_destination':
		case 'single_destination':
			return '/backups';
		case 'drill_never':
		case 'drill_stale':
		case 'deadman_absent':
		case 'deadman_silent':
		case 'admin_tokens':
		case 'admin_unknown':
		case 'audit_broken':
		case 'audit_unreadable':
			return '/health';
		case 'node_unreachable':
		case 'node_disk_full':
		case 'node_disk_filling':
		case 'node_swapping':
		case 'node_load':
		case 'node_reboot_pending':
			return '/nodes';
		case 'topology':
			return '/resilience';
		case 'drift':
			return '/drift';
		case 'exposure_unknown':
		case 'exposed_against_manifest':
		case 'not_published':
		case 'route_not_applied':
		case 'orphan_route':
			return '/exposure';
		case 'secret_never_rotated':
		case 'secret_rotation_due':
			return '/secrets/rotation';
		// The agents are what refuse the controller the day it ends.
		case 'certificate_expiring':
			return '/nodes';
		case 'account_without_mailbox':
			return one ? `/accounts/${one}` : '/accounts?state=without-mailbox';
		case 'account_without_identity':
			return one ? `/accounts/${one}` : '/accounts?state=without-identity';
		case 'account_empty':
			return one ? `/accounts/${one}` : '/accounts?state=empty';
		case 'alias_still_receiving':
			return one ? `/accounts/${one}` : '/accounts';
		case 'safeguard':
			return '/recovery';
		case 'alert':
			return '/alerts';
	}
	const _: never = c;
	return _;
}

/**
 * What a cause says about ONE thing it covers — "never backed up" beside the
 * application's name, where the inbox line says "6 applications never backed up". A
 * cause about the installation itself names nothing, and has no reason to give here.
 */
export function reason(kind: CauseKind): string | null {
	switch (kind) {
		case 'app_failed':
			return m.reason_app_failed();
		case 'app_partial':
			return m.reason_app_partial();
		case 'guide_blocking':
			return m.reason_guide_blocking();
		case 'guide_pending':
			return m.reason_guide_pending();
		case 'catalog_changed':
			return m.reason_catalog_changed();
		case 'job_failed':
			return m.reason_job_failed();
		case 'mail_waiting':
			return m.reason_mail_waiting();
		case 'never_backed_up':
			return m.reason_never_backed_up();
		case 'no_fresh_copy':
			return m.reason_no_fresh_copy();
		case 'one_fresh_copy':
			return m.reason_one_fresh_copy();
		case 'node_unreachable':
			return m.reason_node_unreachable();
		case 'node_disk_full':
			return m.reason_node_disk_full();
		case 'node_disk_filling':
			return m.reason_node_disk_filling();
		case 'node_swapping':
			return m.reason_node_swapping();
		case 'node_load':
			return m.reason_node_load();
		case 'node_reboot_pending':
			return m.reason_node_reboot_pending();
		case 'drift':
			return m.reason_drift();
		case 'exposure_unknown':
			return m.reason_exposure_unknown();
		case 'exposed_against_manifest':
			return m.reason_exposed_against_manifest();
		case 'not_published':
			return m.reason_not_published();
		case 'route_not_applied':
			return m.reason_route_not_applied();
		case 'orphan_route':
			return m.reason_orphan_route();
		case 'secret_never_rotated':
			return m.reason_secret_never_rotated();
		case 'secret_rotation_due':
			return m.reason_secret_rotation_due();
		case 'certificate_expiring':
			return m.reason_certificate_expiring();
		case 'account_without_mailbox':
			return m.reason_account_without_mailbox();
		case 'account_without_identity':
			return m.reason_account_without_identity();
		case 'account_empty':
			return m.reason_account_empty();
		case 'alias_still_receiving':
			return m.reason_alias_still_receiving();
		case 'assertion_broken':
			return m.reason_assertion_broken();
		case 'assertion_unknown':
			return m.reason_assertion_unknown();
		case 'mail_record_wrong':
			return m.reason_mail_record_wrong();
		case 'mail_record_unknown':
			return m.reason_mail_record_unknown();
		case 'mail_blocklists_refused':
			return m.reason_mail_blocklists_refused();
		case 'no_backup_destination':
		case 'single_destination':
		case 'drill_never':
		case 'drill_stale':
		case 'topology':
		case 'deadman_absent':
		case 'deadman_silent':
		case 'admin_tokens':
		case 'admin_unknown':
		case 'audit_broken':
		case 'audit_unreadable':
		case 'safeguard':
		case 'alert':
			return null;
	}
	const _: never = kind;
	return _;
}

/** Why `subject` is in the inbox: each cause naming it, the worst first. */
export function reasons(issues: Issue[], subject: string): { attention: Issue['attention']; text: string }[] {
	return issues.flatMap((i) => {
		const text = reason(i.cause.kind);
		return text !== null && i.subjects.includes(subject) ? [{ attention: i.attention, text }] : [];
	});
}
