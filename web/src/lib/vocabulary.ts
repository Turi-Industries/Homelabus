import { m } from '#lib/paraglide/messages.js';

/**
 * Values the controller accepts as plain strings, so the document cannot list them.
 * ⚠️ Each is checked against its Rust source by `vocabulary.test.ts`: a level added
 * there and not here fails that test, not a person's form.
 */
/** The four permission levels a role holds — the roles themselves are data, read from
 * `/api/access`. */
export const ROLES = {
	user: m.people_role_user,
	viewer: m.people_role_viewer,
	operator: m.people_role_operator,
	admin: m.people_role_admin
} as const;
export type Role = keyof typeof ROLES;

/** A role in one word, where a list has a column for it. */
export const ROLE_NAMES = {
	user: m.people_role_name_user,
	viewer: m.people_role_name_viewer,
	operator: m.people_role_name_operator,
	admin: m.people_role_name_admin
} as const satisfies Record<Role, () => string>;

/**
 * The break-glass safeguards, by the ids `hlb_api::breakglass` stores them under — the
 * inbox names them; `vocabulary.test.ts` holds this to the Rust list.
 */
export const SAFEGUARDS: Record<string, () => string> = {
	'printed-codes': m.safeguard_printed_codes,
	'two-passkeys': m.safeguard_two_passkeys,
	'vaultwarden-local': m.safeguard_vaultwarden_local,
	'pocketid-restored': m.safeguard_pocketid_restored,
	'emergency-vault': m.safeguard_emergency_vault,
	'emergency-kit': m.safeguard_emergency_kit,
	'family-rehearsal': m.safeguard_family_rehearsal
};

/**
 * What each alert rule means, by the name `hlb_metrics::rules::default_rules` gives it
 * — the stored value a mute names. `vocabulary.test.ts` holds this to that list; a rule
 * not here shows the controller's own English, never nothing.
 */
export const ALERT_RULES: Record<string, () => string> = {
	'backup-absent': m.alert_rule_backup_absent,
	'backup-late': m.alert_rule_backup_late,
	'single-copy': m.alert_rule_single_copy,
	'verification-stale': m.alert_rule_verification_stale,
	'app-failed': m.alert_rule_app_failed,
	'node-unreachable': m.alert_rule_node_unreachable,
	'disk-full': m.alert_rule_disk_full,
	'blocking-guides': m.alert_rule_blocking_guides
};

