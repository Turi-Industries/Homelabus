import type { Schemas } from '#lib/api/client.ts';
import { bytes, duration, number, percent } from '#lib/format.ts';
import { m } from '#lib/paraglide/messages.js';

/**
 * How the interface says the structures the server judged. Each `switch` ends on
 * `never` with no `default:` — a variant the controller adds stops the build here
 * instead of being said as nothing.
 */

export function nodeProblem(p: Schemas['NodeProblem']): string {
	switch (p.kind) {
		case 'unreachable':
			return m.words_node_unreachable();
		case 'disk_full':
			return m.words_node_disk_full({ path: p.path, used: percent(p.used) });
		case 'disk_filling':
			return m.words_node_disk_filling({ path: p.path, used: percent(p.used) });
		case 'swapping':
			return m.words_node_swapping();
		case 'load':
			return m.words_node_load({ per_core: p.per_core.toFixed(1) });
		case 'reboot_pending':
			return m.words_node_reboot_pending();
	}
	const _: never = p;
	return _;
}

/** What a machine at this level gives up when stolen — the level is the server's, detected. */
export function protectionLevel(l: Schemas['ProtectionLevel']): string {
	switch (l) {
		case 'A':
			return m.node_detail_protection_a();
		case 'B':
			return m.node_detail_protection_b();
		case 'C':
			return m.node_detail_protection_c();
		case 'D':
			return m.node_detail_protection_d();
	}
	const _: never = l;
	return _;
}

export function coverage(c: Schemas['Coverage']): string {
	switch (c.kind) {
		case 'no_destination':
			return m.words_coverage_no_destination();
		case 'never_backed_up':
			return m.words_coverage_never();
		case 'no_fresh_copy':
			return m.words_coverage_no_fresh_copy({ count: c.destinations });
		case 'one_fresh_copy':
			return m.words_coverage_one_fresh_copy({ count: c.destinations });
		case 'fresh_copies':
			return m.words_coverage_fresh_copies({ count: c.copies });
	}
	const _: never = c;
	return _;
}

export function topology(v: Schemas['TopologyVerdict']): string {
	switch (v.kind) {
		case 'redundancy_illusion':
			return m.words_topology_illusion({ count: v.services });
		case 'concentrated':
			return v.domain === null
				? m.words_topology_concentrated_unknown({ nodes: v.nodes, total: v.total })
				: m.words_topology_concentrated({ nodes: v.nodes, total: v.total, domain: v.domain });
		case 'spread_unknown':
			return m.words_topology_spread_unknown();
		case 'spread':
			return m.words_topology_spread();
		case 'no_machine':
			return m.words_topology_no_machine();
	}
	const _: never = v;
	return _;
}

export function recovery(v: Schemas['Verdict']): string {
	switch (v.kind) {
		case 'none_ever_verified':
			return m.words_recovery_none_ever();
		case 'never_verified':
			return m.words_recovery_never({ count: v.safeguards });
		case 'to_reverify':
			return m.words_recovery_to_reverify({ count: v.safeguards });
		case 'all_recent':
			return m.words_recovery_all_recent();
	}
	const _: never = v;
	return _;
}

export function status(v: Schemas['StatusVerdict']): string {
	switch (v.kind) {
		case 'down':
			return m.words_status_down({ count: v.services });
		case 'incidents':
			return m.words_status_incidents({ count: v.open });
		case 'degraded':
			return m.words_status_degraded({ count: v.services });
		case 'nothing_exposed':
			return m.words_status_nothing_exposed();
		case 'all_operational':
			return m.words_status_all_operational();
	}
	const _: never = v;
	return _;
}

export function service(s: Schemas['ServiceState']): string {
	switch (s) {
		case 'operational':
			return m.words_service_operational();
		case 'degraded':
			return m.words_service_degraded();
		case 'unavailable':
			return m.words_service_unavailable();
		case 'maintenance':
			return m.words_service_maintenance();
	}
	const _: never = s;
	return _;
}

/** The colour role an attention is painted in. */
/** What a state means for the person, and how it is repaired. */
export const accountExplanation: Record<Schemas['AccountState'], () => string> = {
	complete: m.account_explain_complete,
	'without-mailbox': m.account_explain_without_mailbox,
	'without-identity': m.account_explain_without_identity,
	empty: m.account_explain_empty
};

/** A Record, so a state the server adds is missing here at compile time. */
export const accountState: Record<Schemas['AccountState'], () => string> = {
	complete: m.words_account_complete,
	'without-mailbox': m.words_account_without_mailbox,
	'without-identity': m.words_account_without_identity,
	empty: m.words_account_empty
};

export const tone = {
	ok: { text: 'text-ok', border: 'border-ok', bg: 'bg-ok' },
	notice: { text: 'text-attention', border: 'border-attention', bg: 'bg-attention' },
	critical: { text: 'text-critical', border: 'border-critical', bg: 'bg-critical' }
} as const satisfies Record<Schemas['Attention'], object>;

/** How many of `rows` are in each state, as the server judged them — a `Figure`'s bar. */
export function split(rows: readonly { attention: Schemas['Attention'] }[]): Record<Schemas['Attention'], number> {
	const counts = { ok: 0, notice: 0, critical: 0 };
	for (const r of rows) counts[r.attention] += 1;
	return counts;
}

/** A rotation step — a `Record`, so a step the server adds is missing here at compile time. */
export const rotationStep: Record<Schemas['Step'], () => string> = {
	change_in_postgres: m.rotation_step_change_in_postgres,
	write_to_vault: m.rotation_step_write_to_vault,
	redeploy_for_new_variable: m.rotation_step_redeploy_for_new_variable,
	regenerate_in_pocket_id: m.rotation_step_regenerate_in_pocket_id,
	redeploy: m.rotation_step_redeploy,
	create_new_key_in_garage: m.rotation_step_create_new_key_in_garage,
	write_to_vault_garage_never_returns_it: m.rotation_step_write_to_vault_garage_never_returns_it,
	delete_old_key_only_after_app_works: m.rotation_step_delete_old_key_only_after_app_works,
	change_on_stalwart: m.rotation_step_change_on_stalwart,
	redeploy_and_reconfigure_mail: m.rotation_step_redeploy_and_reconfigure_mail,
	do_not_rotate_before_verified_restore: m.rotation_step_do_not_rotate_before_verified_restore,
	add_key_to_restic_repository: m.rotation_step_add_key_to_restic_repository,
	remove_old_restic_key_after_drill: m.rotation_step_remove_old_restic_key_after_drill,
	nothing_reads_it: m.rotation_step_nothing_reads_it,
	create_new_key_at_s3_provider: m.rotation_step_create_new_key_at_s3_provider,
	back_up_and_verify_it_succeeds: m.rotation_step_back_up_and_verify_it_succeeds,
	revoke_old_key_after_backup_passes: m.rotation_step_revoke_old_key_after_backup_passes,
	generate_new_key_at_provider: m.rotation_step_generate_new_key_at_provider,
	reload_what_reads_it: m.rotation_step_reload_what_reads_it
};

export function consequence(c: Schemas['Consequence']): string {
	switch (c.kind) {
		case 'redeploy_app':
			return m.rotation_consequence_redeploy_app({ app: c.app });
		case 'redeploy_whatever_uses_it':
			return m.rotation_consequence_redeploy_whatever();
		case 'reload_is_enough':
			return m.rotation_consequence_reload();
	}
	const _: never = c;
	return _;
}

export const reach: Record<Schemas['Reach'], () => string> = {
	internet: m.security_reach_internet,
	vpn_only: m.security_reach_vpn_only,
	diverged: m.security_reach_diverged
};

/** What an application asks the platform for, before installing it or once it runs. */
export function need(n: Schemas['Need']): string {
	switch (n.kind) {
		case 'database': {
			const base =
				n.extensions.length === 0
					? m.need_database({ engine: n.engine, name: n.name })
					: m.need_database_extensions({ engine: n.engine, name: n.name, extensions: n.extensions.join(', ') });
			// The share of the server every app's budget is summed against.
			return n.connections === null ? base : m.need_database_connections({ need: base, connections: n.connections });
		}
		case 'cache':
			return n.dedicated ? m.need_cache_dedicated({ engine: n.engine }) : m.need_cache_shared({ engine: n.engine });
		case 'sso':
			return sso(n.mode, n.redirects);
		case 'smtp':
			return n.as_person ? m.need_smtp_person() : m.need_smtp();
		case 'mail_account': {
			const mailbox = n.aliases ? m.need_mailbox_aliases() : m.need_mailbox();
			return n.declared_quota_bytes === null ? mailbox : m.need_quota({ need: mailbox, size: bytes(n.declared_quota_bytes) });
		}
		case 'volume': {
			const at = { name: n.name, path: n.path };
			const backed = backup(n.nfs ? m.need_volume_nfs(at) : m.need_volume_local(at), n.backed_up);
			return n.sqlite ? m.need_volume_sqlite({ need: backed }) : backed;
		}
		case 'bucket':
			return backup(m.need_bucket({ name: n.name }), n.backed_up);
	}
	const _: never = n;
	return _;
}

function sso(mode: Schemas['SsoNeed'], redirects: number): string {
	switch (mode) {
		case 'native':
			return m.need_sso_native({ count: redirects });
		case 'proxy_header':
			return m.need_sso_proxy_header();
		case 'proxy_only':
			return m.need_sso_proxy_only();
		case 'excluded':
			return m.need_sso_excluded();
	}
	const _: never = mode;
	return _;
}

function backup(need: string, backedUp: boolean): string {
	return backedUp ? m.need_backed_up({ need }) : m.need_not_backed_up({ need });
}

/** What a health check is about — its title, from what it found. */
export function healthTopic(f: Schemas['HealthFinding']): string {
	switch (f.kind) {
		case 'no_destination':
			return m.health_topic_backups();
		case 'single_destination':
		case 'destinations':
			return m.health_topic_offsite();
		case 'drill_never':
		case 'drill_recent':
		case 'drill_due':
		case 'drill_overdue':
			return m.health_topic_drill();
		case 'heartbeat_absent':
		case 'heartbeat':
			return m.health_topic_deadman();
		case 'admin_unknown':
		case 'admin_single':
		case 'admin_tokens':
			return m.health_topic_admin();
		case 'audit_intact':
		case 'audit_broken':
		case 'audit_unreadable':
			return m.health_topic_audit();
	}
	const _: never = f;
	return _;
}

const DAY = 86_400;

export function healthFinding(f: Schemas['HealthFinding']): string {
	switch (f.kind) {
		case 'no_destination':
			return m.health_no_destination();
		case 'single_destination':
			return m.health_single_destination();
		case 'destinations':
			return m.health_destinations({ count: f.count });
		case 'drill_never':
			return m.health_drill_never();
		case 'drill_recent':
			return f.days === 0 ? m.health_drill_today() : m.health_drill_recent({ ago: duration(f.days * DAY, 'days') });
		case 'drill_due':
			return m.health_drill_due({ ago: duration(f.days * DAY, 'days'), every: duration(f.every_days * DAY, 'days') });
		case 'drill_overdue':
			return m.health_drill_overdue({ ago: duration(f.days * DAY, 'days'), late: duration(f.late_days * DAY, 'days') });
		case 'heartbeat_absent':
			return m.health_heartbeat_absent();
		case 'heartbeat':
			return m.health_heartbeat({ ago: duration(f.age_seconds) });
		case 'admin_unknown':
			return m.health_admin_unknown();
		case 'admin_single':
			return m.health_admin_single();
		case 'admin_tokens':
			return m.health_admin_tokens({ count: number(f.count) });
		case 'audit_intact':
			return m.health_audit_intact();
		case 'audit_broken':
			return m.health_audit_broken();
		case 'audit_unreadable':
			return m.health_audit_unreadable();
	}
	const _: never = f;
	return _;
}

/** What a drift of the domain is of. */
export const domainChange: Record<Schemas['DomainChange'], () => string> = {
	ns: m.domain_change_ns,
	ds: m.domain_change_ds,
	validated: m.domain_change_validated,
	caa: m.domain_change_caa,
	registrar: m.domain_change_registrar,
	statuses: m.domain_change_statuses,
	delegation: m.domain_change_delegation
};

/** One side of a drift: a registrar is one name or none. */
export function driftSide(s: Schemas['DomainDriftSide'], what: Schemas['DomainChange']): string {
	switch (s.kind) {
		case 'names':
			if (s.names.length > 0) return s.names.join(', ');
			return what === 'registrar' ? m.domain_not_named() : m.domain_none();
		case 'validates':
			return s.validates ? m.domain_validates() : m.domain_not_validating();
	}
	const _: never = s;
	return _;
}

/** What the governing CAA lets an ACME account do. */
export const caaVerdict: Record<Schemas['CaaVerdict'], () => string> = {
	pinned: m.domain_verdict_pinned,
	any_account: m.domain_verdict_any_account,
	anyone: m.domain_verdict_anyone,
	refused: m.domain_verdict_refused
};

/** Advice beside a reading; a pin's records are the page's to show. */
export function domainAdvice(a: Schemas['DomainAdvice']): string {
	switch (a.kind) {
		case 'no_transfer_lock':
			return m.domain_advice_no_transfer_lock();
		case 'expires':
			return a.days < 0 ? m.domain_advice_expired() : m.domain_advice_expires({ days: number(a.days) });
		case 'not_signed':
			return m.domain_advice_not_signed();
		case 'signed_not_validating':
			return m.domain_advice_signed_not_validating();
		case 'no_caa':
			return m.domain_advice_no_caa();
		case 'pin':
			switch (a.why) {
				case 'no_authority':
					return m.domain_advice_pin_no_authority({ at: a.at });
				case 'no_account':
					return m.domain_advice_pin_no_account({ at: a.at });
			}
			return a.why satisfies never;
	}
	const _: never = a;
	return _;
}

type QualityRun = Schemas['QualityRun'];
/** The steps of a run: every field the server judges, found by its type. */
export type QualityStep = { [K in keyof QualityRun]: QualityRun[K] extends Schemas['QualityOutcome'] ? K : never }[keyof QualityRun];

/**
 * Each step of an app's proven cycle, in the order it runs. A `Record` over the steps:
 * one the server adds is a missing key here, and the build stops.
 */
const qualitySteps: Record<QualityStep, () => string> = {
	install: m.catalog_step_install,
	update: m.catalog_step_update,
	backup: m.catalog_step_backup,
	restore: m.catalog_step_restore,
	uninstall: m.catalog_step_uninstall
};

export function qualityOutcome(o: Schemas['QualityOutcome']): string {
	switch (o) {
		case 'passed':
			return m.catalog_outcome_passed();
		case 'failed':
			return m.catalog_outcome_failed();
		case 'not_run':
			return m.catalog_outcome_not_run();
	}
	const _: never = o;
	return _;
}

/** A run's steps as they read: `[step, its name, its outcome]`. */
export function qualityRun(run: QualityRun): [QualityStep, string, Schemas['QualityOutcome']][] {
	return (Object.keys(qualitySteps) as QualityStep[]).map((s) => [s, qualitySteps[s](), run[s]]);
}

/** How long an app has been maintained in its catalog. */
export function maintained(q: Schemas['CatalogQuality']): string {
	return q.maintained_months === 0 ? m.catalog_maintained_new() : m.catalog_maintained({ count: q.maintained_months });
}
