import DatabaseBackup from '@lucide/svelte/icons/database-backup';
import { m } from '#lib/paraglide/messages.js';
import type { Module } from '../module';

export const module: Module = {
	id: 'data',
	area: 'console',
	order: 30,
	label: m.nav_data,
	icon: DatabaseBackup,
	pages: [
		{ path: '/backups', label: m.page_data_coverage, reads: ['/api/coverage'] },
		{ path: '/backups/runs', label: m.page_data_runs, reads: ['/api/backups'] }
	],
	causes: ['never_backed_up', 'no_backup_destination', 'no_fresh_copy', 'one_fresh_copy', 'single_destination', 'drill_never', 'drill_stale'],
};
