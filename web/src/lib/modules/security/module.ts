import Shield from '@lucide/svelte/icons/shield';
import { m } from '#lib/paraglide/messages.js';
import type { Module } from '../module';

export const module: Module = {
	id: 'security',
	area: 'console',
	order: 40,
	label: m.nav_security,
	icon: Shield,
	pages: [
		{ path: '/exposure', label: m.page_security_exposure, reads: ['/api/exposure'] },
		{ path: '/secrets', label: m.page_security_secrets, reads: ['/api/secrets'] },
		{ path: '/secrets/rotation', label: m.page_security_rotation, reads: ['/api/secrets/rotation'] }
	],
	causes: ['exposure_unknown', 'exposed_against_manifest', 'not_published', 'route_not_applied', 'orphan_route', 'secret_never_rotated', 'secret_rotation_due', 'certificate_expiring', 'assertion_broken', 'assertion_unknown', 'mail_record_wrong', 'mail_record_unknown', 'mail_blocklists_refused'],
};
